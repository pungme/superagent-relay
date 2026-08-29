import { describe, it, expect, beforeEach } from 'vitest'
import { generateKeyPairSync, sign, createPublicKey, verify as edVerify, randomBytes } from 'node:crypto'
import { Room, b64, unb64, route, machineIdToKey, CLOSE, LIMITS, type Socket } from '../src/core.js'

class FakeSocket implements Socket {
  sent: string[] = []
  closed: { code: number; reason: string } | null = null
  send(text: string): void {
    this.sent.push(text)
  }
  close(code: number, reason: string): void {
    this.closed = { code, reason }
  }
  last(): Record<string, unknown> {
    return JSON.parse(this.sent[this.sent.length - 1])
  }
}

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')
const { publicKey, privateKey } = generateKeyPairSync('ed25519')
const rawPub = (publicKey.export({ format: 'der', type: 'spki' }) as Buffer).subarray(-32)
const machineId = rawPub.toString('hex')

let now = 1_000_000
const hooks = {
  verify: async (pk: Uint8Array, msg: Uint8Array, sig: Uint8Array) =>
    edVerify(
      null,
      Buffer.from(msg),
      createPublicKey({
        key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(pk)]),
        format: 'der',
        type: 'spki'
      }),
      Buffer.from(sig)
    ),
  randomNonce: () => {
    const out = new Uint8Array(new ArrayBuffer(32))
    out.set(randomBytes(32))
    return out
  },
  now: () => now
}

async function authedRoom(): Promise<{ room: Room; mac: FakeSocket }> {
  const room = new Room(machineId, machineIdToKey(machineId)!, hooks)
  const mac = new FakeSocket()
  room.machineConnected(mac)
  const nonce = unb64(mac.last().nonce as string)
  const sig = sign(null, Buffer.from(nonce), privateKey)
  await room.machineFrame(mac, JSON.stringify({ t: 'auth', sig: b64(new Uint8Array(sig)) }))
  return { room, mac }
}

describe('Room', () => {
  beforeEach(() => {
    now = 1_000_000
  })

  it('authenticates the machine with a signed nonce', async () => {
    const { room, mac } = await authedRoom()
    expect(mac.last()).toEqual({ t: 'ok' })
    expect(room.hasMachine).toBe(true)
  })

  it('rejects a bad signature and a stale auth', async () => {
    const room = new Room(machineId, machineIdToKey(machineId)!, hooks)
    const mac = new FakeSocket()
    room.machineConnected(mac)
    await room.machineFrame(mac, JSON.stringify({ t: 'auth', sig: b64(new Uint8Array(64)) }))
    expect(mac.closed?.code).toBe(CLOSE.unauthorized)

    const late = new FakeSocket()
    room.machineConnected(late)
    now += LIMITS.authTimeoutMs + 1
    room.expirePendingAuth()
    expect(late.closed?.code).toBe(CLOSE.unauthorized)
  })

  it('refuses phones while the machine is offline', () => {
    const room = new Room(machineId, machineIdToKey(machineId)!, hooks)
    const phone = new FakeSocket()
    expect(room.clientConnected(phone)).toBeNull()
    expect(phone.sent).toEqual(['{"t":"offline"}'])
    expect(phone.closed?.code).toBe(CLOSE.offline)
  })

  it('pipes frames both ways without touching them', async () => {
    const { room, mac } = await authedRoom()
    const phone = new FakeSocket()
    const id = room.clientConnected(phone)!
    expect(mac.last()).toEqual({ t: 'open', c: id })

    room.clientFrame(id, 'CIPHERTEXT-1')
    expect(mac.last()).toEqual({ t: 'msg', c: id, d: 'CIPHERTEXT-1' })

    await room.machineFrame(mac, JSON.stringify({ t: 'msg', c: id, d: 'CIPHERTEXT-2' }))
    expect(phone.sent).toEqual(['CIPHERTEXT-2'])

    room.clientClosed(id)
    expect(mac.last()).toEqual({ t: 'close', c: id })
  })

  it('drops every phone when the machine goes away', async () => {
    const { room, mac } = await authedRoom()
    const a = new FakeSocket()
    const b = new FakeSocket()
    room.clientConnected(a)
    room.clientConnected(b)
    room.machineClosed(mac)
    expect(a.closed?.code).toBe(CLOSE.machineGone)
    expect(b.closed?.code).toBe(CLOSE.machineGone)
    expect(room.clientCount).toBe(0)
  })

  it('lets a newer machine connection replace the old one', async () => {
    const { room, mac } = await authedRoom()
    const phone = new FakeSocket()
    const id = room.clientConnected(phone)!
    const mac2 = new FakeSocket()
    room.machineConnected(mac2)
    const nonce = unb64(mac2.last().nonce as string)
    const sig = sign(null, Buffer.from(nonce), privateKey)
    await room.machineFrame(mac2, JSON.stringify({ t: 'auth', sig: b64(new Uint8Array(sig)) }))
    expect(mac.closed?.code).toBe(CLOSE.replaced)
    // The surviving phone is re-announced to the new machine socket.
    expect(mac2.sent).toContain(JSON.stringify({ t: 'open', c: id }))
  })

  it('caps clients and frame size', async () => {
    const { room, mac } = await authedRoom()
    for (let i = 0; i < LIMITS.maxClients; i++) room.clientConnected(new FakeSocket())
    const extra = new FakeSocket()
    expect(room.clientConnected(extra)).toBeNull()
    expect(extra.closed?.code).toBe(CLOSE.tooMany)

    const big = new FakeSocket()
    room.machineClosed(mac)
    const { room: r2, mac: m2 } = await authedRoom()
    const id = r2.clientConnected(big)!
    r2.clientFrame(id, 'x'.repeat(LIMITS.maxFrameBytes + 1))
    expect(big.closed?.code).toBe(CLOSE.protocol)
    expect(m2.last()).toEqual({ t: 'close', c: id })
  })

  it('adopts surviving sockets after a host rebuild without a new challenge', async () => {
    const room = new Room(machineId, machineIdToKey(machineId)!, hooks)
    const mac = new FakeSocket()
    const phone = new FakeSocket()
    room.adoptMachine(mac)
    room.adoptClient('c7', phone)
    expect(room.hasMachine).toBe(true)
    expect(room.isMachine(mac)).toBe(true)
    room.clientFrame('c7', 'X')
    expect(mac.last()).toEqual({ t: 'msg', c: 'c7', d: 'X' })
    // Fresh client ids continue past the adopted ones.
    const next = new FakeSocket()
    expect(room.clientConnected(next)).toBe('c8')
  })

  it('ignores a machine that talks before authenticating', async () => {
    const room = new Room(machineId, machineIdToKey(machineId)!, hooks)
    const stranger = new FakeSocket()
    await room.machineFrame(stranger, JSON.stringify({ t: 'msg', c: 'c1', d: 'x' }))
    expect(stranger.closed?.code).toBe(CLOSE.unauthorized)
  })
})

describe('helpers', () => {
  it('routes machine and client paths', () => {
    expect(route(`/m/${machineId}`)).toEqual({ role: 'machine', machineId })
    expect(route(`/c/${machineId}/`)).toEqual({ role: 'client', machineId })
    expect(route('/c/nope')).toBeNull()
    expect(route('/healthz')).toBeNull()
  })
  it('round-trips base64', () => {
    const bytes = new Uint8Array(randomBytes(40))
    expect(unb64(b64(bytes))).toEqual(bytes)
  })
})
