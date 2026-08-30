import { DurableObject } from 'cloudflare:workers'
import { Room, route, machineIdToKey, isAllowed, CLOSE, type Socket, type RoomHooks, type Quota } from './core'
import { makePusherWith, readPushConfig } from './push'

/**
 * The relay as a Cloudflare Worker: one Durable Object per machine id, using
 * the WebSocket Hibernation API so an idle room costs nothing.
 */

export interface Env {
  ROOMS: DurableObjectNamespace<MachineRoom>
  APNS_KEY?: string
  APNS_KEY_ID?: string
  APNS_TEAM_ID?: string
  APNS_BUNDLE_ID?: string
  /** Optional: only these machine ids (or ≥8-char prefixes) may use this relay. */
  RELAY_ALLOWED_MACHINES?: string
  /** Lets `POST /admin/quota/<machineId>` clear today's byte count. */
  RELAY_ADMIN_TOKEN?: string
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url)
    if (url.pathname === '/healthz') {
      return Response.json({ ok: true, push: !!readPushConfig(env as unknown as Record<string, string | undefined>) })
    }
    // Clear a machine's daily byte count. Guarded by a secret, because anyone
    // who could call it freely could also erase the guardrail. Exists so a
    // budget spent by a bug is recoverable before midnight UTC.
    if (url.pathname.startsWith('/admin/quota/')) {
      const token = request.headers.get('x-admin-token') ?? ''
      const want = env.RELAY_ADMIN_TOKEN ?? ''
      if (!want || token !== want) return new Response('unauthorized', { status: 401 })
      const machineId = url.pathname.slice('/admin/quota/'.length)
      if (!/^[0-9a-f]{64}$/.test(machineId)) return new Response('bad machine id', { status: 400 })
      const room = env.ROOMS.get(env.ROOMS.idFromName(machineId))
      return room.fetch(new Request('https://relay.internal/reset-quota', { method: 'POST' }))
    }
    const target = route(url.pathname)
    if (!target) return new Response('not found', { status: 404 })
    if (!isAllowed(target.machineId, env.RELAY_ALLOWED_MACHINES)) {
      return new Response('this relay only serves machines on its allowlist', { status: 403 })
    }
    if (request.headers.get('Upgrade') !== 'websocket') {
      return new Response('expected websocket', { status: 426 })
    }
    const id = env.ROOMS.idFromName(target.machineId)
    return env.ROOMS.get(id).fetch(request)
  }
}

interface Attachment {
  role: 'machine' | 'client'
  clientId?: string
  /** Set once the machine's signature checked out; survives hibernation. */
  authed?: boolean
  /** The phone's address, for the per-address cap after a rebuild. */
  address?: string
}

export class MachineRoom extends DurableObject<Env> {
  private room: Room | null = null
  private machineId = ''
  private quotaLoaded = false

  /**
   * The machine this object serves. The object is created by
   * idFromName(machineId), so the name survives every eviction — a fresh
   * instance must not depend on having seen the original request.
   */
  private machineIdFor(hint?: string): string {
    return this.machineId || hint || this.ctx.id.name || ''
  }

  private ensureRoom(hint?: string): Room | null {
    if (this.room) return this.room
    const machineId = this.machineIdFor(hint)
    const key = machineIdToKey(machineId)
    if (!key) return null
    this.machineId = machineId
    const env = this.env
    const cfg = readPushConfig(env as unknown as Record<string, string | undefined>)
    const hooks: RoomHooks = {
      verify: async (publicKey, message, signature) => {
        const k = await crypto.subtle.importKey('raw', publicKey, { name: 'Ed25519' }, false, ['verify'])
        return crypto.subtle.verify('Ed25519', k, signature, message)
      },
      randomNonce: () => crypto.getRandomValues(new Uint8Array(new ArrayBuffer(32))),
      now: () => Date.now(),
      push: cfg ? makePusherWith(cfg, crypto.subtle, (u, i) => fetch(u, i)) : undefined,
      // Once per MB, so a day's count survives eviction without a write per frame.
      saveQuota: (q) => void this.ctx.storage.put('quota', q)
    }
    this.room = new Room(machineId, key, hooks)
    // Sockets that outlived the object (hibernation) re-attach to the fresh
    // Room from their attachments — the machine without a new challenge, since
    // it was recorded as authenticated when it passed the first one.
    for (const ws of this.ctx.getWebSockets()) {
      const att = ws.deserializeAttachment() as Attachment | null
      if (!att) continue
      if (att.role === 'machine') {
        if (att.authed) this.room.adoptMachine(wrap(ws))
        else ws.close(CLOSE.unauthorized, 'auth interrupted, reconnect')
      } else if (att.clientId) {
        this.room.adoptClient(att.clientId, wrap(ws), att.address)
      }
    }
    // Clients that were attached while no machine survived get the honest answer.
    if (!this.room.hasMachine) {
      for (const ws of this.ctx.getWebSockets()) {
        const att = ws.deserializeAttachment() as Attachment | null
        if (att?.role === 'client') ws.close(CLOSE.machineGone, 'machine disconnected')
      }
    }
    return this.room
  }

  /** Today's byte count, read once per object lifetime before any frame is charged. */
  private async hydrate(room: Room): Promise<void> {
    if (this.quotaLoaded) return
    this.quotaLoaded = true
    room.restoreQuota((await this.ctx.storage.get<Quota>('quota')) ?? null)
  }

  async fetch(request: Request): Promise<Response> {
    if (new URL(request.url).pathname === '/reset-quota') {
      await this.ctx.storage.delete('quota')
      this.quotaLoaded = true
      this.room?.clearQuota()
      return Response.json({ ok: true, cleared: true })
    }
    const target = route(new URL(request.url).pathname)
    if (!target) return new Response('not found', { status: 404 })
    const room = this.ensureRoom(target.machineId)
    if (!room) return new Response('bad machine id', { status: 400 })
    await this.hydrate(room)
    const address = request.headers.get('CF-Connecting-IP') ?? undefined

    const pair = new WebSocketPair()
    const [client, server] = [pair[0], pair[1]]
    this.ctx.acceptWebSocket(server, [target.role])
    const sock = wrap(server)
    if (target.role === 'machine') {
      server.serializeAttachment({ role: 'machine' } satisfies Attachment)
      room.machineConnected(sock)
      // Auth deadline: alarms are the hibernation-safe timer.
      await this.ctx.storage.setAlarm(Date.now() + 11_000)
    } else {
      const id = room.clientConnected(sock, address)
      if (id) server.serializeAttachment({ role: 'client', clientId: id, address } satisfies Attachment)
    }
    return new Response(null, { status: 101, webSocket: client })
  }

  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    const room = this.ensureRoom()
    const att = ws.deserializeAttachment() as Attachment | null
    if (!room) return
    await this.hydrate(room)
    const text = typeof message === 'string' ? message : new TextDecoder().decode(message)
    if (!att) return
    if (att.role === 'machine') {
      const sock = wrap(ws)
      // The attachment, not object identity, says who the machine is: after a
      // wake the runtime may hand us a different JS object for the same socket.
      if (att.authed && !room.isMachine(sock)) room.adoptMachine(sock)
      await room.machineFrame(sock, text)
      // Remember a successful auth on the socket itself, for the next wake.
      if (!att.authed && room.isMachine(sock)) {
        ws.serializeAttachment({ role: 'machine', authed: true } satisfies Attachment)
      }
    } else if (att.clientId) room.clientFrame(att.clientId, text)
  }

  async webSocketClose(ws: WebSocket): Promise<void> {
    // Even on a cold instance: the Mac must hear that its phone left.
    const room = this.ensureRoom()
    if (!room) return
    const att = ws.deserializeAttachment() as Attachment | null
    if (!att) return
    if (att.role === 'machine') room.machineClosed(wrap(ws))
    else if (att.clientId) room.clientClosed(att.clientId)
  }

  async webSocketError(ws: WebSocket): Promise<void> {
    await this.webSocketClose(ws)
  }

  async alarm(): Promise<void> {
    this.ensureRoom()?.expirePendingAuth()
  }
}

// The Room compares Socket identity, so each WebSocket must map to one wrapper.
const wrappers = new WeakMap<WebSocket, Socket>()
function wrap(ws: WebSocket): Socket {
  let w = wrappers.get(ws)
  if (!w) {
    w = {
      send: (text) => {
        try {
          ws.send(text)
        } catch (e) {
          console.log(`[room] send failed readyState=${ws.readyState}: ${(e as Error).message}`)
        }
      },
      close: (code, reason) => {
        try {
          ws.close(code, reason)
        } catch {
          /* already closed */
        }
      }
    }
    wrappers.set(ws, w)
  }
  return w
}
