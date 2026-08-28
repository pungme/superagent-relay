import { describe, it, expect, afterAll } from 'vitest'
import { generateKeyPairSync, sign } from 'node:crypto'
import { WebSocket } from 'ws'
import { startRelay } from '../src/node.js'
import { b64, unb64, CLOSE } from '../src/core.js'

const server = startRelay(0)
const port = (): number => (server.address() as { port: number }).port
afterAll(() => server.close())

const { publicKey, privateKey } = generateKeyPairSync('ed25519')
const machineId = (publicKey.export({ format: 'der', type: 'spki' }) as Buffer)
  .subarray(-32)
  .toString('hex')

function next(ws: WebSocket): Promise<string> {
  return new Promise((resolve) => ws.once('message', (d) => resolve(d.toString())))
}
function closed(ws: WebSocket): Promise<number> {
  return new Promise((resolve) => ws.once('close', (code) => resolve(code)))
}

async function connectMachine(): Promise<WebSocket> {
  const ws = new WebSocket(`ws://127.0.0.1:${port()}/m/${machineId}`)
  const challenge = JSON.parse(await next(ws))
  const sig = sign(null, Buffer.from(unb64(challenge.nonce)), privateKey)
  ws.send(JSON.stringify({ t: 'auth', sig: b64(new Uint8Array(sig)) }))
  expect(JSON.parse(await next(ws))).toEqual({ t: 'ok' })
  return ws
}

describe('relay over real sockets', () => {
  it('answers health', async () => {
    const res = await fetch(`http://127.0.0.1:${port()}/healthz`)
    expect(await res.json()).toMatchObject({ ok: true })
  })

  it('tells a phone when the machine is offline', async () => {
    const phone = new WebSocket(`ws://127.0.0.1:${port()}/c/${machineId}`)
    expect(await next(phone)).toBe('{"t":"offline"}')
    expect(await closed(phone)).toBe(CLOSE.offline)
  })

  it('pipes ciphertext between a phone and its machine', async () => {
    const mac = await connectMachine()
    const phone = new WebSocket(`ws://127.0.0.1:${port()}/c/${machineId}`)
    const open = JSON.parse(await next(mac))
    expect(open.t).toBe('open')

    phone.send('hello-from-phone')
    expect(JSON.parse(await next(mac))).toEqual({ t: 'msg', c: open.c, d: 'hello-from-phone' })

    mac.send(JSON.stringify({ t: 'msg', c: open.c, d: 'hello-from-mac' }))
    expect(await next(phone)).toBe('hello-from-mac')

    mac.close()
    expect(await closed(phone)).toBe(CLOSE.machineGone)
  })

  it('rejects unknown paths', async () => {
    const ws = new WebSocket(`ws://127.0.0.1:${port()}/nope`)
    await expect(
      new Promise((_, reject) => ws.once('error', reject))
    ).rejects.toThrow()
  })
})
