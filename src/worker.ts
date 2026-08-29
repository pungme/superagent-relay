import { DurableObject } from 'cloudflare:workers'
import { Room, route, machineIdToKey, CLOSE, type Socket, type RoomHooks } from './core'
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
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url)
    if (url.pathname === '/healthz') {
      return Response.json({ ok: true, push: !!readPushConfig(env as unknown as Record<string, string | undefined>) })
    }
    const target = route(url.pathname)
    if (!target) return new Response('not found', { status: 404 })
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
}

export class MachineRoom extends DurableObject<Env> {
  private room: Room | null = null
  private machineId = ''

  private ensureRoom(machineId: string): Room | null {
    if (this.room) return this.room
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
      push: cfg ? makePusherWith(cfg, crypto.subtle, (u, i) => fetch(u, i)) : undefined
    }
    this.room = new Room(machineId, key, hooks)
    // Sockets that survived hibernation re-attach to the fresh Room.
    for (const ws of this.ctx.getWebSockets()) {
      const att = ws.deserializeAttachment() as Attachment | null
      if (!att) continue
      if (att.role === 'machine') {
        // The machine has to prove itself again after a hibernation wake.
        ws.close(CLOSE.replaced, 'relay restarted, reconnect')
      } else {
        ws.close(CLOSE.machineGone, 'relay restarted, reconnect')
      }
    }
    return this.room
  }

  async fetch(request: Request): Promise<Response> {
    const target = route(new URL(request.url).pathname)
    if (!target) return new Response('not found', { status: 404 })
    const room = this.ensureRoom(target.machineId)
    if (!room) return new Response('bad machine id', { status: 400 })

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
      const id = room.clientConnected(sock)
      if (id) server.serializeAttachment({ role: 'client', clientId: id } satisfies Attachment)
    }
    return new Response(null, { status: 101, webSocket: client })
  }

  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    const room = this.ensureRoom(this.machineId)
    const att = ws.deserializeAttachment() as Attachment | null
    if (!room) return
    const text = typeof message === 'string' ? message : new TextDecoder().decode(message)
    if (!att) return
    if (att.role === 'machine') await room.machineFrame(wrap(ws), text)
    else if (att.clientId) room.clientFrame(att.clientId, text)
  }

  async webSocketClose(ws: WebSocket): Promise<void> {
    const room = this.room
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
    this.room?.expirePendingAuth()
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
