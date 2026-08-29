// Smoke-test a running relay (any host) end to end: usage: node test/live.mjs ws://127.0.0.1:8790
import { generateKeyPairSync, sign } from 'node:crypto'

const base = (process.argv[2] ?? 'ws://127.0.0.1:8787').replace(/\/+$/, '')
const { publicKey, privateKey } = generateKeyPairSync('ed25519')
const machineId = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex')
const b64 = (u8) => Buffer.from(u8).toString('base64')
const unb64 = (s) => new Uint8Array(Buffer.from(s, 'base64'))

// Every socket buffers what it receives from the moment it is created, so a
// frame that arrives before we ask for it is never lost.
const inboxes = new WeakMap()
const track = (ws) => {
  const q = { items: [], waiters: [], closed: null }
  ws.addEventListener('message', (ev) => {
    const text = String(ev.data)
    const w = q.waiters.findIndex((x) => x.pred(text))
    if (w >= 0) q.waiters.splice(w, 1)[0].resolve(text)
    else q.items.push(text)
  })
  ws.addEventListener('close', (e) => {
    q.closed = e.code
    for (const w of q.waiters.splice(0)) w.reject(new Error(`closed ${e.code}`))
  })
  inboxes.set(ws, q)
  return ws
}
const wait = (ws, pred = () => true) =>
  new Promise((resolve, reject) => {
    const q = inboxes.get(ws)
    const i = q.items.findIndex(pred)
    if (i >= 0) return resolve(q.items.splice(i, 1)[0])
    if (q.closed !== null) return reject(new Error(`closed ${q.closed}`))
    q.waiters.push({ pred, resolve, reject })
  })
const closed = (ws) => new Promise((r) => ws.addEventListener('close', (e) => r(e.code), { once: true }))

let failures = 0
const check = (name, ok) => {
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}`)
  if (!ok) failures++
}

// 1. health
const health = await (await fetch(base.replace(/^ws/, 'http') + '/healthz')).json()
check('healthz', health.ok === true)

// 2. phone before machine → offline
{
  const phone = track(new WebSocket(`${base}/c/${machineId}`))
  const first = await wait(phone).catch((e) => e.message)
  check('phone told offline', first === '{"t":"offline"}')
  check('phone closed 4404', (await closed(phone)) === 4404)
}

// 3. machine auth
const mac = track(new WebSocket(`${base}/m/${machineId}`))
const challenge = JSON.parse(await wait(mac))
check('challenge received', challenge.t === 'challenge' && typeof challenge.nonce === 'string')
mac.send(JSON.stringify({ t: 'auth', sig: b64(sign(null, Buffer.from(unb64(challenge.nonce)), privateKey)) }))
check('auth ok', (await wait(mac)) === '{"t":"ok"}')

// 4. pipe
const phone = track(new WebSocket(`${base}/c/${machineId}`))
await new Promise((r) => phone.addEventListener('open', r, { once: true }))
const open = JSON.parse(await wait(mac, (t) => t.includes('"open"')))
check('machine sees open', open.t === 'open' && typeof open.c === 'string')
phone.send('CIPHERTEXT-FROM-PHONE')
const msg = JSON.parse(await wait(mac, (t) => t.includes('"msg"')))
check('phone → machine verbatim', msg.c === open.c && msg.d === 'CIPHERTEXT-FROM-PHONE')
mac.send(JSON.stringify({ t: 'msg', c: open.c, d: 'CIPHERTEXT-FROM-MAC' }))
check('machine → phone verbatim', (await wait(phone)) === 'CIPHERTEXT-FROM-MAC')
mac.send('{"t":"ping"}')
check('ping/pong', (await wait(mac, (t) => t.includes('pong'))) === '{"t":"pong"}')

// 5. machine leaves → phone dropped with 4410
const phoneClose = closed(phone)
mac.close()
check('phone dropped 4410 when machine leaves', (await phoneClose) === 4410)

// 6. bad signature refused
{
  const bad = track(new WebSocket(`${base}/m/${machineId}`))
  await wait(bad)
  bad.send(JSON.stringify({ t: 'auth', sig: b64(new Uint8Array(64)) }))
  check('bad signature closed 4401', (await closed(bad)) === 4401)
}

console.log(failures ? `\n${failures} failure(s)` : '\nall good')
process.exit(failures ? 1 : 0)
