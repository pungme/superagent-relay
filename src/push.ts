/**
 * APNs sender used by both hosts. The machine asks the relay to push because
 * the relay is the one place the project's .p8 key can live without being in
 * every user's hands. Payloads are whatever the machine sends — the relay adds
 * only the transport headers.
 *
 * Machine frame: {t:"push", token, env:"production"|"sandbox", payload, collapseId?, pushType?}
 */

export interface PushConfig {
  keyPem: string
  keyId: string
  teamId: string
  bundleId: string
}

export interface PushRequest {
  token: string
  env?: 'production' | 'sandbox'
  payload: Record<string, unknown>
  collapseId?: string
  pushType?: 'alert' | 'background' | 'liveactivity'
  priority?: 5 | 10
}

export function readPushConfig(env: Record<string, string | undefined>): PushConfig | null {
  const { APNS_KEY, APNS_KEY_ID, APNS_TEAM_ID, APNS_BUNDLE_ID } = env
  if (!APNS_KEY || !APNS_KEY_ID || !APNS_TEAM_ID || !APNS_BUNDLE_ID) return null
  return {
    keyPem: APNS_KEY.replace(/\\n/g, '\n'),
    keyId: APNS_KEY_ID,
    teamId: APNS_TEAM_ID,
    bundleId: APNS_BUNDLE_ID
  }
}

function b64url(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function pemToPkcs8(pem: string): Uint8Array<ArrayBuffer> {
  const body = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '')
  const bin = atob(body)
  const out = new Uint8Array(new ArrayBuffer(bin.length))
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

/**
 * Provider token (ES256 JWT), cached and refreshed every 50 minutes — Apple
 * wants one that is older than 20 minutes and younger than 60.
 */
export class ApnsTokenSource {
  private key: CryptoKey | null = null
  private token: { value: string; issuedAt: number } | null = null

  constructor(
    private cfg: PushConfig,
    private subtle: SubtleCrypto,
    private now: () => number = () => Date.now()
  ) {}

  async get(): Promise<string> {
    const now = this.now()
    if (this.token && now - this.token.issuedAt < 50 * 60 * 1000) return this.token.value
    if (!this.key) {
      this.key = await this.subtle.importKey(
        'pkcs8',
        pemToPkcs8(this.cfg.keyPem),
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['sign']
      )
    }
    const enc = new TextEncoder()
    const header = b64url(enc.encode(JSON.stringify({ alg: 'ES256', kid: this.cfg.keyId })))
    const claims = b64url(
      enc.encode(JSON.stringify({ iss: this.cfg.teamId, iat: Math.floor(now / 1000) }))
    )
    const signingInput = `${header}.${claims}`
    // WebCrypto ECDSA yields the raw r||s (IEEE P1363) form JWT wants.
    const sig = await this.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      this.key,
      enc.encode(signingInput)
    )
    const value = `${signingInput}.${b64url(new Uint8Array(sig))}`
    this.token = { value, issuedAt: now }
    return value
  }
}

export type Fetch = (url: string, init: RequestInit) => Promise<Response>

/** Builds the push hook. `fetch` is injectable so tests never touch Apple. */
export function makePusherWith(
  cfg: PushConfig,
  subtle: SubtleCrypto,
  fetchImpl: Fetch,
  now?: () => number
): (req: Record<string, unknown>) => Promise<void> {
  const tokens = new ApnsTokenSource(cfg, subtle, now)
  return async (raw) => {
    const req = raw as unknown as PushRequest
    if (typeof req.token !== 'string' || !/^[0-9a-fA-F]{32,}$/.test(req.token)) {
      throw new Error('bad device token')
    }
    if (!req.payload || typeof req.payload !== 'object') throw new Error('missing payload')
    const host =
      req.env === 'sandbox' ? 'https://api.sandbox.push.apple.com' : 'https://api.push.apple.com'
    const pushType = req.pushType ?? 'alert'
    const topic =
      pushType === 'liveactivity' ? `${cfg.bundleId}.push-type.liveactivity` : cfg.bundleId
    const headers: Record<string, string> = {
      authorization: `bearer ${await tokens.get()}`,
      'apns-topic': topic,
      'apns-push-type': pushType,
      'apns-priority': String(req.priority ?? (pushType === 'background' ? 5 : 10)),
      'content-type': 'application/json'
    }
    if (req.collapseId) headers['apns-collapse-id'] = req.collapseId
    const res = await fetchImpl(`${host}/3/device/${req.token}`, {
      method: 'POST',
      headers,
      body: JSON.stringify(req.payload)
    })
    if (!res.ok) {
      const body = await res.text().catch(() => '')
      throw new Error(`apns ${res.status}: ${body.slice(0, 200)}`)
    }
  }
}

/** Build the hook from env vars, with the host's HTTP/2-capable fetch. */
export function makePusher(
  env: Record<string, string | undefined>,
  fetchImpl: Fetch
): ((req: Record<string, unknown>) => Promise<void>) | null {
  const cfg = readPushConfig(env)
  if (!cfg) return null
  return makePusherWith(cfg, globalThis.crypto.subtle, fetchImpl)
}
