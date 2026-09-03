/**
 * The relay, independent of where it runs.
 *
 * One Room per machine id. The Mac holds a single authenticated socket; any
 * number of phones (up to a cap) attach as clients. The room forwards frames
 * between them verbatim — it never parses, stores or logs a payload. All it
 * knows is who is connected and how many bytes they push.
 *
 * Machine side wire format (JSON text frames):
 *   relay → mac   {t:"challenge", nonce}      first frame; answer within 10 s
 *   mac → relay   {t:"auth", sig}             base64 Ed25519 signature of nonce bytes
 *   relay → mac   {t:"ok"} | {t:"bye", reason}
 *   relay → mac   {t:"open", c}               a phone attached
 *   relay → mac   {t:"msg", c, d}             frame from phone c (d = opaque string)
 *   relay → mac   {t:"close", c}              phone c left
 *   mac → relay   {t:"msg", c, d}             frame to phone c
 *   mac → relay   {t:"close", c}              drop phone c
 *   mac → relay   {t:"push", ...}             ask the relay to send an APNs push (see push.ts)
 *   either        {t:"ping"} / {t:"pong"}
 *
 * Client side: raw text frames only. Whatever a phone sends is delivered to
 * the Mac as `d`; whatever the Mac sends for that client arrives as the raw
 * string. If no Mac is connected the phone gets {t:"offline"} and is closed.
 */

/** Bytes WebCrypto accepts on every host (never a SharedArrayBuffer view). */
export type Bytes = Uint8Array<ArrayBuffer>

export interface Socket {
  send(text: string): void
  close(code: number, reason: string): void
}

export interface RoomHooks {
  /** Ed25519 verification: raw 32-byte public key, message, signature. */
  verify(publicKey: Bytes, message: Bytes, signature: Bytes): Promise<boolean>
  randomNonce(): Bytes
  /** Handle a push request from the machine. Optional — relays without a key skip it. */
  push?(req: Record<string, unknown>): Promise<void>
  now(): number
  log?(line: string): void
  /** Persist the day's byte count (called at most once per MB relayed). */
  saveQuota?(q: Quota): void
}

export const LIMITS = {
  maxFrameBytes: 1_048_576, // 1 MB — a screenshot fits, nothing bigger is expected
  maxClients: 8,
  /** Phones from one address in one room; keeps a stranger from filling the slots. */
  clientsPerAddress: 3,
  /**
   * A client is dead if it has not been heard from in this long.
   *
   * Phones ping every 25s, so a live one is never quiet for more than that. A
   * socket that dies without a close frame — the phone loses signal, changes
   * network, is put in a pocket — leaves an entry nothing ever removes, and
   * three of those from one address silently locked the real phone out with
   * "too many connections from this address". Four missed pings is dead.
   */
  clientStaleMs: 100_000,
  bytesPerSecond: 2_000_000, // per machine, both directions
  /** Per machine per UTC day. A day of heavy use is tens of MB; this is a ceiling, not a target. */
  bytesPerDay: 100_000_000,
  authTimeoutMs: 10_000
}

/** Bytes a machine has relayed today, as the host persists it across restarts. */
export interface Quota {
  /** UTC day as YYYY-MM-DD. */
  day: string
  bytes: number
}

export const CLOSE = {
  offline: 4404,
  machineGone: 4410,
  unauthorized: 4401,
  tooMany: 4429,
  replaced: 4409,
  protocol: 4400,
  /** The machine used its day's byte budget; back tomorrow (UTC). */
  quota: 4413,
  /** This relay only serves machines on its allowlist. */
  forbidden: 4403
} as const

interface Client {
  id: string
  socket: Socket
  address?: string
  /** When a frame last arrived from this client. See LIMITS.clientStaleMs. */
  lastSeen: number
}

export class Room {
  private mac: Socket | null = null
  private pendingMac: { socket: Socket; nonce: Bytes; deadline: number } | null = null
  private clients = new Map<string, Client>()
  private nextClient = 1
  // Token bucket for byte rate, per machine.
  private tokens = LIMITS.bytesPerSecond
  private lastRefill: number
  private quota: Quota = { day: '', bytes: 0 }
  private savedMb = 0

  constructor(
    readonly machineId: string,
    private publicKey: Bytes,
    private hooks: RoomHooks
  ) {
    this.lastRefill = hooks.now()
  }

  get hasMachine(): boolean {
    return this.mac !== null
  }
  get clientCount(): number {
    return this.clients.size
  }
  /** Today's relayed bytes for this machine (for the host to persist or show). */
  get usage(): Quota {
    return { ...this.quota }
  }
  /** Restore a persisted count; anything from another day is ignored. */
  /**
   * Forget today's byte count. The budget is a guardrail against a runaway
   * client, not a bill — when the runaway has been fixed there has to be a way
   * back in before midnight UTC.
   */
  clearQuota(): void {
    this.quota = { day: utcDay(this.hooks.now()), bytes: 0 }
    this.savedMb = 0
  }

  restoreQuota(q: Quota | null | undefined): void {
    if (q && q.day === utcDay(this.hooks.now())) {
      this.quota = { ...q }
      this.savedMb = Math.floor(q.bytes / 1_000_000)
    }
  }

  // --- machine ---------------------------------------------------------------

  /** A socket claiming to be the machine. Starts the challenge; nothing else yet. */
  machineConnected(socket: Socket): void {
    const nonce = this.hooks.randomNonce()
    this.pendingMac = { socket, nonce, deadline: this.hooks.now() + LIMITS.authTimeoutMs }
    socket.send(JSON.stringify({ t: 'challenge', nonce: b64(nonce) }))
  }

  /** Called by the host on a timer or before handling frames. */
  expirePendingAuth(): void {
    if (this.pendingMac && this.hooks.now() > this.pendingMac.deadline) {
      this.pendingMac.socket.close(CLOSE.unauthorized, 'auth timeout')
      this.pendingMac = null
    }
  }

  async machineFrame(socket: Socket, text: string): Promise<void> {
    if (this.overDailyBudget(text.length)) {
      this.closeForQuota()
      return
    }
    if (!this.charge(text.length)) return // over budget: drop silently
    if (this.pendingMac && this.pendingMac.socket === socket) {
      await this.finishAuth(text)
      return
    }
    if (socket !== this.mac) {
      socket.close(CLOSE.unauthorized, 'not authenticated')
      return
    }
    let frame: { t?: string; c?: string; d?: unknown }
    try {
      frame = JSON.parse(text)
    } catch {
      return
    }
    switch (frame.t) {
      case 'msg': {
        const client = frame.c ? this.clients.get(frame.c) : undefined
        if (client && typeof frame.d === 'string') client.socket.send(frame.d)
        return
      }
      case 'close': {
        const client = frame.c ? this.clients.get(frame.c) : undefined
        if (client) {
          this.clients.delete(client.id)
          client.socket.close(1000, 'closed by machine')
        }
        return
      }
      case 'ping':
        socket.send('{"t":"pong"}')
        return
      case 'push':
        if (this.hooks.push) {
          this.hooks.push(frame as Record<string, unknown>).catch((e) =>
            this.hooks.log?.(`push failed: ${(e as Error).message}`)
          )
        }
        return
      default:
        return
    }
  }

  private async finishAuth(text: string): Promise<void> {
    const pending = this.pendingMac!
    let frame: { t?: string; sig?: string }
    try {
      frame = JSON.parse(text)
    } catch {
      frame = {}
    }
    let ok = false
    if (frame.t === 'auth' && typeof frame.sig === 'string') {
      try {
        ok = await this.hooks.verify(this.publicKey, pending.nonce, unb64(frame.sig))
      } catch {
        ok = false
      }
    }
    this.pendingMac = null
    if (!ok) {
      pending.socket.close(CLOSE.unauthorized, 'bad signature')
      return
    }
    // A second Mac process (crashed one still lingering, or a restart) wins
    // over the old socket; the old one is told why.
    if (this.mac) this.mac.close(CLOSE.replaced, 'replaced by a newer connection')
    this.mac = pending.socket
    this.mac.send('{"t":"ok"}')
    // Phones that arrived before the Mac re-authenticated are announced now.
    for (const c of this.clients.values()) this.mac.send(JSON.stringify({ t: 'open', c: c.id }))
  }

  /** True if this socket is the authenticated machine. */
  isMachine(socket: Socket): boolean {
    return this.mac === socket
  }

  /**
   * Re-attach sockets that outlived the Room (a hibernating host rebuilt it).
   * No challenge: the host only adopts a machine it recorded as authenticated.
   */
  adoptMachine(socket: Socket): void {
    if (this.mac && this.mac !== socket) this.mac.close(CLOSE.replaced, 'replaced by a newer connection')
    this.mac = socket
  }

  adoptClient(id: string, socket: Socket, address?: string): void {
    // Fresh, not stale: waking from hibernation says nothing about whether this
    // phone is still there, and reaping the whole room on wake would be worse
    // than the leak. Its next ping — 25s at most — settles it either way.
    this.clients.set(id, { id, socket, address, lastSeen: this.hooks.now() })
    const n = Number(id.slice(1))
    if (Number.isFinite(n) && n >= this.nextClient) this.nextClient = n + 1
  }

  machineClosed(socket: Socket): void {
    if (this.pendingMac?.socket === socket) this.pendingMac = null
    if (this.mac !== socket) return
    this.mac = null
    for (const c of this.clients.values()) c.socket.close(CLOSE.machineGone, 'machine disconnected')
    this.clients.clear()
  }

  // --- clients ---------------------------------------------------------------

  /** Returns the client id, or null if refused (socket already closed). */
  clientConnected(socket: Socket, address?: string): string | null {
    if (!this.mac) {
      socket.send('{"t":"offline"}')
      socket.close(CLOSE.offline, 'machine offline')
      return null
    }
    // Before any cap is enforced: a cap that counts dead entries is a lockout.
    this.sweepStaleClients()
    if (this.clients.size >= LIMITS.maxClients) {
      socket.close(CLOSE.tooMany, 'too many clients')
      return null
    }
    if (address) {
      let same = 0
      for (const c of this.clients.values()) if (c.address === address) same++
      if (same >= LIMITS.clientsPerAddress) {
        socket.close(CLOSE.tooMany, 'too many connections from this address')
        return null
      }
    }
    const id = `c${this.nextClient++}`
    this.clients.set(id, { id, socket, address, lastSeen: this.hooks.now() })
    this.mac.send(JSON.stringify({ t: 'open', c: id }))
    this.announceUsage()
    return id
  }

  clientFrame(id: string, text: string): void {
    if (!this.mac || !this.clients.has(id)) return
    this.clients.get(id)!.lastSeen = this.hooks.now()
    if (text.length > LIMITS.maxFrameBytes) {
      this.clients.get(id)!.socket.close(CLOSE.protocol, 'frame too large')
      this.clients.delete(id)
      this.mac.send(JSON.stringify({ t: 'close', c: id }))
      return
    }
    if (this.overDailyBudget(text.length)) {
      this.closeForQuota()
      return
    }
    if (!this.charge(text.length)) return
    this.mac.send(JSON.stringify({ t: 'msg', c: id, d: text }))
  }

  /**
   * Drop clients that have gone quiet.
   *
   * Nothing else ever removed them. A phone that vanishes without a close frame
   * left an entry in this map for the lifetime of the room, and the only thing
   * that cleared them was the Mac's own socket dropping — which is why "wake the
   * Mac up and it works again" was the reliable cure for a Mac that had never
   * been asleep.
   */
  private sweepStaleClients(): void {
    const cutoff = this.hooks.now() - LIMITS.clientStaleMs
    for (const c of [...this.clients.values()]) {
      if (c.lastSeen > cutoff) continue
      this.clients.delete(c.id)
      this.hooks.log?.(`${this.machineId.slice(0, 8)} dropped silent client ${c.id}`)
      try {
        c.socket.close(CLOSE.machineGone, 'no keepalive')
      } catch {
        // Already gone: the entry was the only thing left of it.
      }
      this.mac?.send(JSON.stringify({ t: 'close', c: c.id }))
    }
  }

  clientClosed(id: string): void {
    if (!this.clients.delete(id)) return
    this.mac?.send(JSON.stringify({ t: 'close', c: id }))
  }

  // --- limits ----------------------------------------------------------------

  /**
   * What today has cost, to whoever is connected. Sent once per megabyte and
   * when someone joins, so a phone and a Mac can both show it before the
   * budget runs out rather than discovering it as an outage.
   */
  private announceUsage(): void {
    const frame = JSON.stringify({
      t: 'usage',
      day: this.quota.day,
      bytes: this.quota.bytes,
      limit: LIMITS.bytesPerDay
    })
    this.mac?.send(frame)
    for (const c of this.clients.values()) c.socket.send(frame)
  }

  private charge(bytes: number): boolean {
    const now = this.hooks.now()
    const elapsed = Math.max(0, now - this.lastRefill) / 1000
    this.tokens = Math.min(LIMITS.bytesPerSecond, this.tokens + elapsed * LIMITS.bytesPerSecond)
    this.lastRefill = now
    if (this.tokens < bytes) return false
    this.tokens -= bytes
    this.quota.bytes += bytes
    const mb = Math.floor(this.quota.bytes / 1_000_000)
    if (mb > this.savedMb) {
      this.savedMb = mb
      this.hooks.saveQuota?.(this.usage)
      this.announceUsage()
    }
    return true
  }

  /** Rolls the day over first; true if this frame would exceed today's budget. */
  private overDailyBudget(bytes: number): boolean {
    const day = utcDay(this.hooks.now())
    if (this.quota.day !== day) {
      this.quota = { day, bytes: 0 }
      this.savedMb = 0
    }
    return this.quota.bytes + bytes > LIMITS.bytesPerDay
  }

  /** Everyone is told the same thing; the Mac's reconnects fail the same way until tomorrow. */
  private closeForQuota(): void {
    const reason = 'daily byte budget used up; back tomorrow (UTC)'
    this.hooks.log?.(`${this.machineId.slice(0, 8)} ${reason}`)
    for (const c of this.clients.values()) c.socket.close(CLOSE.quota, reason)
    this.clients.clear()
    this.mac?.close(CLOSE.quota, reason)
    this.mac = null
    this.pendingMac?.socket.close(CLOSE.quota, reason)
    this.pendingMac = null
  }
}

/** YYYY-MM-DD in UTC. */
export function utcDay(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10)
}

/**
 * Whether a machine may use this relay. `list` is the RELAY_ALLOWED_MACHINES
 * setting: empty means open to all, otherwise comma/space-separated machine
 * ids (a prefix of at least 8 hex characters is enough to name one).
 */
export function isAllowed(machineId: string, list: string | undefined | null): boolean {
  const entries = (list ?? '')
    .split(/[\s,]+/)
    .map((e) => e.trim().toLowerCase())
    .filter((e) => e.length >= 8)
  if (!entries.length) return true
  return entries.some((e) => machineId.startsWith(e))
}

// --- helpers ---------------------------------------------------------------

export function b64(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s)
}

export function unb64(s: string): Bytes {
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/'))
  const out = new Uint8Array(new ArrayBuffer(bin.length))
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

/** A machine id is the hex of a raw 32-byte Ed25519 public key. */
export function machineIdToKey(id: string): Bytes | null {
  if (!/^[0-9a-f]{64}$/.test(id)) return null
  const out = new Uint8Array(new ArrayBuffer(32))
  for (let i = 0; i < 32; i++) out[i] = parseInt(id.slice(i * 2, i * 2 + 2), 16)
  return out
}

/** Route a request path: /m/<id> for machines, /c/<id> for clients. */
export function route(path: string): { role: 'machine' | 'client'; machineId: string } | null {
  const m = /^\/(m|c)\/([0-9a-f]{64})\/?$/.exec(path)
  if (!m) return null
  return { role: m[1] === 'm' ? 'machine' : 'client', machineId: m[2] }
}
