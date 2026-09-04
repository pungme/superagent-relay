import { describe, it, expect, beforeEach } from 'vitest'
import { generateKeyPairSync, sign, createPublicKey, verify as edVerify, randomBytes } from 'node:crypto'
import { Room, b64, unb64, route, machineIdToKey, isAllowed, utcDay, CLOSE, LIMITS, type Socket } from '../src/core.js'

class FakeSocket implements Socket {
  sent: string[] = []
  closed: { code: number; reason: string } | null = null
  send(text: string): void {
    this.sent.push(text)
  }
  close(code: number, reason: string): void {
    this.closed = { code, reason }
  }
  /** Everything but the room's own usage bookkeeping, which can arrive at any time. */
  get traffic(): string[] {
    return this.sent.filter((t) => !t.includes('"t":"usage"'))
  }
  last(): Record<string, unknown> {
    const t = this.traffic
    return JSON.parse(t[t.length - 1])
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

  it('tells a quota-locked machine\'s phone WHY, not a bare offline', async () => {
    const { room, mac } = await authedRoom()
    room.restoreQuota({ day: utcDay(now), bytes: LIMITS.bytesPerDay - 1 })
    await room.machineFrame(mac, 'x'.repeat(10)) // trips the budget, machine kicked
    expect(room.hasMachine).toBe(false)
    const phone = new FakeSocket()
    expect(room.clientConnected(phone)).toBeNull()
    expect(phone.sent).toEqual(['{"t":"offline","reason":"quota"}'])
    expect(phone.closed?.code).toBe(CLOSE.quota)
  })

  it('splits the day\'s bytes by direction', async () => {
    const { room, mac } = await authedRoom()
    const phone = new FakeSocket()
    const id = room.clientConnected(phone, '203.0.113.9')!
    await room.machineFrame(mac, JSON.stringify({ t: 'msg', c: id, d: 'to the phone' }))
    room.clientFrame(id, 'to the mac')
    expect(room.usage.m2p).toBeGreaterThan(0)
    expect(room.usage.p2m).toBe('to the mac'.length)
    expect(room.usage.bytes).toBe((room.usage.m2p ?? 0) + (room.usage.p2m ?? 0))
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
    expect(phone.traffic).toEqual(['CIPHERTEXT-2'])

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

  it('caps phones per address inside a room', async () => {
    const { room } = await authedRoom()
    const ok = Array.from({ length: LIMITS.clientsPerAddress }, () => new FakeSocket())
    for (const s of ok) expect(room.clientConnected(s, '203.0.113.9')).not.toBeNull()
    const extra = new FakeSocket()
    expect(room.clientConnected(extra, '203.0.113.9')).toBeNull()
    expect(extra.closed?.code).toBe(CLOSE.tooMany)
    // A different address still gets in.
    expect(room.clientConnected(new FakeSocket(), '198.51.100.4')).not.toBeNull()
  })

  /**
   * The lockout this was reported as: "my phone cannot reach the Mac", from a
   * Mac that was awake the whole time and had never slept.
   *
   * A phone that vanishes without a close frame — lost signal, changed network,
   * went in a pocket — left an entry nothing removed. Three of those from one
   * address filled clientsPerAddress, and the real phone was refused. The only
   * thing that had ever cleared them was the Mac's own socket dropping, which is
   * why waking the Mac "fixed" it and why the cause looked like sleep.
   */
  it('does not let phones that went quiet lock out the one that is really there', async () => {
    const { room } = await authedRoom()
    const ghosts = Array.from({ length: LIMITS.clientsPerAddress }, () => new FakeSocket())
    for (const s of ghosts) expect(room.clientConnected(s, '203.0.113.9')).not.toBeNull()

    // Before: full, and a fourth is refused.
    expect(room.clientConnected(new FakeSocket(), '203.0.113.9')).toBeNull()

    // They stop pinging. Four missed keepalives later they are not there.
    now += LIMITS.clientStaleMs + 1
    const real = new FakeSocket()
    expect(room.clientConnected(real, '203.0.113.9')).not.toBeNull()
    expect(real.closed).toBeNull()
    for (const g of ghosts) expect(g.closed?.code).toBe(CLOSE.machineGone)
  })

  it('keeps a phone that is still pinging, however long it has been connected', async () => {
    const { room } = await authedRoom()
    const phone = new FakeSocket()
    const id = room.clientConnected(phone, '203.0.113.9')!
    // Well past the staleness window, but it keeps saying hello.
    for (let i = 0; i < 10; i++) {
      now += LIMITS.clientStaleMs / 2
      room.clientFrame(id, '{"t":"ping"}')
    }
    now += LIMITS.clientStaleMs / 2
    room.clientConnected(new FakeSocket(), '198.51.100.4')
    expect(phone.closed).toBeNull()
  })

  /** The Mac has to learn the phone is gone, or it keeps a session open for it. */
  it('tells the Mac about each client it reaps', async () => {
    const { room, mac } = await authedRoom()
    const ghost = new FakeSocket()
    const id = room.clientConnected(ghost, '203.0.113.9')!
    now += LIMITS.clientStaleMs + 1
    room.clientConnected(new FakeSocket(), '198.51.100.4')
    expect(mac.traffic).toContain(JSON.stringify({ t: 'close', c: id }))
  })

  it('closes everyone when the day\'s byte budget is used up, and resets at midnight UTC', async () => {
    const { room, mac } = await authedRoom()
    const phone = new FakeSocket()
    const id = room.clientConnected(phone, '203.0.113.9')!
    // Pretend most of the day's budget is already spent (as a host would restore it).
    room.restoreQuota({ day: utcDay(now), bytes: LIMITS.bytesPerDay - 10 })
    room.clientFrame(id, 'x'.repeat(5))
    expect(mac.last()).toMatchObject({ t: 'msg', c: id })
    room.clientFrame(id, 'x'.repeat(20))
    expect(phone.closed?.code).toBe(CLOSE.quota)
    expect(mac.closed?.code).toBe(CLOSE.quota)
    expect(room.hasMachine).toBe(false)
    // Next day: the count starts over.
    now += 24 * 3600 * 1000
    const { room: fresh, mac: mac2 } = await authedRoom()
    fresh.restoreQuota({ day: utcDay(now - 24 * 3600 * 1000), bytes: LIMITS.bytesPerDay })
    const p2 = new FakeSocket()
    const id2 = fresh.clientConnected(p2)!
    fresh.clientFrame(id2, 'hello')
    expect(mac2.last()).toMatchObject({ t: 'msg', c: id2, d: 'hello' })
  })

  it('persists the day\'s count once per MB', async () => {
    const saved: unknown[] = []
    const room = new Room(machineId, machineIdToKey(machineId)!, { ...hooks, saveQuota: (q) => saved.push(q) })
    const mac = new FakeSocket()
    room.machineConnected(mac)
    const nonce = unb64(mac.last().nonce as string)
    const sig = sign(null, Buffer.from(nonce), privateKey)
    await room.machineFrame(mac, JSON.stringify({ t: 'auth', sig: b64(new Uint8Array(sig)) }))
    const phone = new FakeSocket()
    const id = room.clientConnected(phone)!
    for (let i = 0; i < 3; i++) {
      now += 1000
      room.clientFrame(id, 'x'.repeat(700_000))
    }
    expect(saved.length).toBe(2) // crossed 1 MB and 2 MB
    expect(room.usage.bytes).toBeGreaterThan(2_000_000)
  })

  it('reads an allowlist as open when empty, by prefix otherwise', () => {
    expect(isAllowed(machineId, undefined)).toBe(true)
    expect(isAllowed(machineId, '  ')).toBe(true)
    expect(isAllowed(machineId, machineId.slice(0, 12))).toBe(true)
    expect(isAllowed(machineId, `deadbeef00, ${machineId}`)).toBe(true)
    expect(isAllowed(machineId, 'deadbeef00')).toBe(false)
    expect(isAllowed(machineId, 'abc')).toBe(true) // too short to name anyone: ignored
  })
})
