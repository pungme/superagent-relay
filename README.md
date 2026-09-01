# superagent-relay

The meeting point between [Superagent desktop](https://github.com/pungme/superagent-desktop) and
its iPhone app. Both sides dial **out** to it, so it works from anywhere without touching a router.
It forwards end-to-end-encrypted frames and stores nothing — it can't read a message even if it
wanted to. The only thing it can do on its own is send an Apple push notification when the Mac
asks it to.

Superagent ships with a default relay baked in (`wss://superagent-relay.superagent-relay.workers.dev`, this code on Cloudflare). Run your own if you'd rather; it's one URL to change
on the Mac (Settings → Phone) and the phone picks it up from the pairing QR.

Three repositories: [desktop](https://github.com/pungme/superagent-desktop) ·
[iOS](https://github.com/pungme/superagent-ios) · **relay** (this one).

## Self-host

```sh
docker run -p 8787:8787 ghcr.io/pungme/superagent-relay
# or
npm install && npm run build && PORT=8787 npm start
```

Health: `GET /healthz`. That's the whole thing — no database, no config required.

Smoke-test any running relay (either host): `npm run smoke -- ws://127.0.0.1:8787`.

**Push notifications** (optional): give the relay an APNs key and it can wake phones when the
agent needs you. Set `APNS_KEY` (the `.p8` contents), `APNS_KEY_ID`, `APNS_TEAM_ID`,
`APNS_BUNDLE_ID`. Without them everything still works while the app is open.

## Cloudflare (free tier)

```sh
npm install
npx wrangler login
npx wrangler secret put APNS_KEY      # optional, see above
npm run worker:deploy
```

One Durable Object per Mac, hibernating when idle.

## Limits, abuse, and the default relay

The relay the desktop app points at by default (`wss://superagent-relay.superagent-relay.workers.dev`)
is run by the project on Cloudflare's free tier, best-effort. It is fine for personal use; if you
depend on it, run your own — it is one `wrangler deploy` and one URL in Settings → Phone.

Every room is capped so one machine can't crowd out the others (numbers in `src/core.ts` `LIMITS`):

| limit | value | what happens |
|---|---|---|
| frame size | 1 MiB | the sender is closed (`4400`) — Cloudflare's WebSocket message ceiling |
| phones per machine | 8 | extra phones are refused (`4429`) |
| phones per address per machine | 3 | keeps a stranger who learned a machine id from filling the slots (`4429`) |
| bytes per second per machine | 2 MB/s | frames over the rate are dropped |
| bytes per UTC day per machine | 500 MB | everyone in the room is closed with `4413`; the machine is back after midnight UTC |

The daily count survives Durable Object eviction (persisted once per MB).

To make a deployment private, set an allowlist — comma-separated machine ids (the hex shown under
*Machine id* in Settings → Phone; a prefix of 8+ characters is enough):

```sh
npx wrangler secret put RELAY_ALLOWED_MACHINES     # Cloudflare
RELAY_ALLOWED_MACHINES=2642b2caf479 npx tsx src/node.ts   # Node
```

Machines not on the list get HTTP 403 at connect. The relay never holds a key that could read a
frame: an attacker with the URL and a machine id can occupy slots or spend budget, not read or forge.

## How it works

- Mac connects to `wss://relay/m/<machineId>` and proves it owns the id by signing a nonce
  (the id *is* its Ed25519 public key). Phones connect to `wss://relay/c/<machineId>`.
- Frames are opaque strings. The relay wraps them in `{t:"msg", c:<client>, d:…}` towards the
  Mac and unwraps them towards the phone. Limits: 1 MB per frame, 8 phones per Mac, 2 MB/s.
- No Mac connected → the phone gets `{"t":"offline"}` and close code 4404. Mac drops → phones
  get close code 4410 and reconnect later.

`src/core.ts` is the host-independent logic; `src/node.ts` and `src/worker.ts` are the two hosts.

MIT.
