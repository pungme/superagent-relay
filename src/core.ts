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
}

export const LIMITS = {
  maxFrameBytes: 1_048_576, // 1 MB — a screenshot fits, nothing bigger is expected
  maxClients: 8,
  bytesPerSecond: 2_000_000, // per machine, both directions
  authTimeoutMs: 10_000
}

export const CLOSE = {
  offline: 4404,
  machineGone: 4410,
  unauthorized: 4401,
  tooMany: 4429,
  replaced: 4409,
  protocol: 4400
} as const

interface Client {
  id: string
  socket: Socket
}

export class Room {
  private mac: Socket | null = null
  private pendingMac: { socket: Socket; nonce: Bytes; deadline: number } | null = null
  private clients = new Map<string, Client>()
  private nextClient = 1
  // Token bucket for byte rate, per machine.
  private tokens = LIMITS.bytesPerSecond
  private lastRefill: number

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

  adoptClient(id: string, socket: Socket): void {
    this.clients.set(id, { id, socket })
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
  clientConnected(socket: Socket): string | null {
    if (!this.mac) {
      socket.send('{"t":"offline"}')
      socket.close(CLOSE.offline, 'machine offline')
      return null
    }
    if (this.clients.size >= LIMITS.maxClients) {
      socket.close(CLOSE.tooMany, 'too many clients')
      return null
    }
    const id = `c${this.nextClient++}`
    this.clients.set(id, { id, socket })
    this.mac.send(JSON.stringify({ t: 'open', c: id }))
    return id
  }

  clientFrame(id: string, text: string): void {
    if (!this.mac || !this.clients.has(id)) return
    if (text.length > LIMITS.maxFrameBytes) {
      this.clients.get(id)!.socket.close(CLOSE.protocol, 'frame too large')
      this.clients.delete(id)
      this.mac.send(JSON.stringify({ t: 'close', c: id }))
      return
    }
    if (!this.charge(text.length)) return
    this.mac.send(JSON.stringify({ t: 'msg', c: id, d: text }))
  }

  clientClosed(id: string): void {
    if (!this.clients.delete(id)) return
    this.mac?.send(JSON.stringify({ t: 'close', c: id }))
  }

  // --- limits ----------------------------------------------------------------

  private charge(bytes: number): boolean {
    const now = this.hooks.now()
    const elapsed = Math.max(0, now - this.lastRefill) / 1000
    this.tokens = Math.min(LIMITS.bytesPerSecond, this.tokens + elapsed * LIMITS.bytesPerSecond)
    this.lastRefill = now
    if (this.tokens < bytes) return false
    this.tokens -= bytes
    return true
  }
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
