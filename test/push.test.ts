import { describe, it, expect } from 'vitest'
import { generateKeyPairSync, verify } from 'node:crypto'
import { makePusherWith, readPushConfig } from '../src/push.js'

const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
const pem = privateKey.export({ format: 'pem', type: 'pkcs8' }) as string

const cfg = readPushConfig({
  APNS_KEY: pem,
  APNS_KEY_ID: 'KEY123',
  APNS_TEAM_ID: 'TEAM456',
  APNS_BUNDLE_ID: 'dev.superagent.ios'
})!

describe('push', () => {
  it('reads config only when every field is present', () => {
    expect(readPushConfig({})).toBeNull()
    expect(cfg.bundleId).toBe('dev.superagent.ios')
  })

  it('sends a signed provider token and the right APNs headers', async () => {
    const calls: { url: string; init: RequestInit }[] = []
    const push = makePusherWith(cfg, globalThis.crypto.subtle, async (url, init) => {
      calls.push({ url, init })
      return new Response('', { status: 200 })
    })
    const token = 'ab'.repeat(32)
    await push({
      token,
      env: 'sandbox',
      payload: { aps: { alert: { title: 'hi' } } },
      collapseId: 'chat-1'
    })
    expect(calls).toHaveLength(1)
    expect(calls[0].url).toBe(`https://api.sandbox.push.apple.com/3/device/${token}`)
    const h = calls[0].init.headers as Record<string, string>
    expect(h['apns-topic']).toBe('dev.superagent.ios')
    expect(h['apns-push-type']).toBe('alert')
    expect(h['apns-priority']).toBe('10')
    expect(h['apns-collapse-id']).toBe('chat-1')

    // The bearer is a real ES256 JWT for our key id and team.
    const jwt = h.authorization.replace('bearer ', '')
    const [header, claims, sig] = jwt.split('.')
    const dec = (s: string): unknown =>
      JSON.parse(Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString())
    expect(dec(header)).toEqual({ alg: 'ES256', kid: 'KEY123' })
    expect(dec(claims)).toMatchObject({ iss: 'TEAM456' })
    const ok = verify(
      'sha256',
      Buffer.from(`${header}.${claims}`),
      { key: publicKey, dsaEncoding: 'ieee-p1363' },
      Buffer.from(sig.replace(/-/g, '+').replace(/_/g, '/'), 'base64')
    )
    expect(ok).toBe(true)
  })

  it('reuses the token within 50 minutes and rotates after', async () => {
    let now = 1_700_000_000_000
    const seen = new Set<string>()
    const push = makePusherWith(
      cfg,
      globalThis.crypto.subtle,
      async (_u, init) => {
        seen.add((init.headers as Record<string, string>).authorization)
        return new Response('', { status: 200 })
      },
      () => now
    )
    const req = { token: 'cd'.repeat(32), payload: { aps: {} } }
    await push(req)
    now += 10 * 60 * 1000
    await push(req)
    expect(seen.size).toBe(1)
    now += 45 * 60 * 1000
    await push(req)
    expect(seen.size).toBe(2)
  })

  it('surfaces APNs errors and validates input', async () => {
    const push = makePusherWith(cfg, globalThis.crypto.subtle, async () =>
      new Response('{"reason":"BadDeviceToken"}', { status: 400 })
    )
    await expect(push({ token: 'zz', payload: {} })).rejects.toThrow('bad device token')
    await expect(push({ token: 'ab'.repeat(32), payload: { aps: {} } })).rejects.toThrow(
      'apns 400'
    )
  })
})
