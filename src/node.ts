import { createServer, IncomingMessage } from 'node:http'
import { createPublicKey, randomBytes, verify as edVerify } from 'node:crypto'
import { WebSocketServer, WebSocket } from 'ws'
import { Room, route, machineIdToKey, isAllowed, CLOSE, LIMITS, type Socket, type RoomHooks } from './core.js'
import { makePusher } from './push.js'

/**
 * The relay as a plain Node process — what `docker run` gives a self-hoster.
 *   PORT        listen port (default 8787)
 *   APNS_KEY, APNS_KEY_ID, APNS_TEAM_ID, APNS_BUNDLE_ID   optional, enables push
 */

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')

const hooks: RoomHooks = {
  async verify(publicKey, message, signature) {
    const key = createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(publicKey)]),
      format: 'der',
      type: 'spki'
    })
    return edVerify(null, Buffer.from(message), key, Buffer.from(signature))
  },
  randomNonce: () => {
    const out = new Uint8Array(new ArrayBuffer(32))
    out.set(randomBytes(32))
    return out
  },
  now: () => Date.now(),
  log: (line) => console.log(`[relay] ${line}`)
}

const pusher = makePusher(process.env, nodeH2Fetch)
if (pusher) hooks.push = pusher
else console.log('[relay] push disabled (no APNS_* configuration)')

const rooms = new Map<string, Room>()
function roomFor(machineId: string): Room | null {
  let room = rooms.get(machineId)
  if (!room) {
    const key = machineIdToKey(machineId)
    if (!key) return null
    room = new Room(machineId, key, hooks)
    rooms.set(machineId, room)
  }
  return room
}

function wrap(ws: WebSocket): Socket {
  return {
    send: (text) => {
      if (ws.readyState === WebSocket.OPEN) ws.send(text)
    },
    close: (code, reason) => {
      try {
        ws.close(code, reason)
      } catch {
        ws.terminate()
      }
    }
  }
}

export function startRelay(port = Number(process.env.PORT ?? 8787)): ReturnType<typeof createServer> {
  const server = createServer((req, res) => {
    if (req.url === '/healthz') {
      res.writeHead(200, { 'content-type': 'application/json' }).end(
        JSON.stringify({ ok: true, rooms: rooms.size, push: !!pusher })
      )
      return
    }
    res.writeHead(404).end()
  })
  const wss = new WebSocketServer({ noServer: true, maxPayload: LIMITS.maxFrameBytes })

  server.on('upgrade', (req: IncomingMessage, socket, head) => {
    const target = route(new URL(req.url ?? '/', 'http://x').pathname)
    if (!target) {
      socket.write('HTTP/1.1 404 Not Found\r\n\r\n')
      socket.destroy()
      return
    }
    if (!isAllowed(target.machineId, process.env.RELAY_ALLOWED_MACHINES)) {
      socket.write('HTTP/1.1 403 Forbidden\r\n\r\n')
      socket.destroy()
      return
    }
    // Behind a proxy the real address is in X-Forwarded-For; otherwise the socket's.
    const fwd = req.headers['x-forwarded-for']
    const address = (Array.isArray(fwd) ? fwd[0] : fwd)?.split(',')[0].trim() || req.socket.remoteAddress || undefined
    wss.handleUpgrade(req, socket, head, (ws) => attach(ws, target.role, target.machineId, address))
  })

  // Liveness: ws-level ping every 30 s; a socket that never pongs is dropped.
  const alive = new WeakMap<WebSocket, boolean>()
  const sweep = setInterval(() => {
    for (const ws of wss.clients) {
      if (alive.get(ws) === false) {
        ws.terminate()
        continue
      }
      alive.set(ws, false)
      ws.ping()
    }
    for (const room of rooms.values()) room.expirePendingAuth()
  }, 30_000)
  sweep.unref()

  function attach(ws: WebSocket, role: 'machine' | 'client', machineId: string, address?: string): void {
    const room = roomFor(machineId)
    if (!room) {
      ws.close(CLOSE.protocol, 'bad machine id')
      return
    }
    alive.set(ws, true)
    ws.on('pong', () => alive.set(ws, true))
    const sock = wrap(ws)
    if (role === 'machine') {
      room.machineConnected(sock)
      ws.on('message', (data) => {
        void room.machineFrame(sock, data.toString())
      })
      ws.on('close', () => room.machineClosed(sock))
      ws.on('error', () => room.machineClosed(sock))
      return
    }
    const id = room.clientConnected(sock, address)
    if (!id) return
    ws.on('message', (data) => room.clientFrame(id, data.toString()))
    ws.on('close', () => room.clientClosed(id))
    ws.on('error', () => room.clientClosed(id))
  }

  server.listen(port, () => console.log(`[relay] listening on :${port}`))
  return server
}

/**
 * Node's fetch speaks HTTP/1.1 to origins and APNs resets those — so this
 * host talks HTTP/2 directly. Minimal on purpose.
 */
async function nodeH2Fetch(url: string, init: RequestInit): Promise<Response> {
  const http2 = await import('node:http2')
  const u = new URL(url)
  return new Promise((resolve, reject) => {
    const client = http2.connect(u.origin)
    client.on('error', reject)
    const headers: Record<string, string> = {
      ':method': init.method ?? 'POST',
      ':path': u.pathname,
      ...(init.headers as Record<string, string>)
    }
    const req = client.request(headers)
    let status = 0
    const chunks: Buffer[] = []
    req.on('response', (h) => {
      status = Number(h[':status'] ?? 0)
    })
    req.on('data', (c: Buffer) => chunks.push(c))
    req.on('end', () => {
      client.close()
      resolve(new Response(Buffer.concat(chunks).toString('utf8'), { status }))
    })
    req.on('error', (e) => {
      client.close()
      reject(e)
    })
    req.end(typeof init.body === 'string' ? init.body : undefined)
  })
}

const isMain = process.argv[1] && /node\.(t|j)s$/.test(process.argv[1])
if (isMain) startRelay()
