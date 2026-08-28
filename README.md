# superagent-relay

The meeting point between [SuperAgent desktop](https://github.com/pungme/superagent-desktop) and
its iPhone app. Both sides dial **out** to it, so it works from anywhere without touching a router.
It forwards end-to-end-encrypted frames and stores nothing — it can't read a message even if it
wanted to. The only thing it can do on its own is send an Apple push notification when the Mac
asks it to.

SuperAgent ships with a default relay baked in. Run your own if you'd rather; it's one URL to change
on the Mac (Settings → Phone) and the phone picks it up from the pairing QR.

## Self-host

```sh
docker run -p 8787:8787 ghcr.io/pungme/superagent-relay
# or
npm install && npm run build && PORT=8787 npm start
```

Health: `GET /healthz`. That's the whole thing — no database, no config required.

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

## How it works

- Mac connects to `wss://relay/m/<machineId>` and proves it owns the id by signing a nonce
  (the id *is* its Ed25519 public key). Phones connect to `wss://relay/c/<machineId>`.
- Frames are opaque strings. The relay wraps them in `{t:"msg", c:<client>, d:…}` towards the
  Mac and unwraps them towards the phone. Limits: 1 MB per frame, 8 phones per Mac, 2 MB/s.
- No Mac connected → the phone gets `{"t":"offline"}` and close code 4404. Mac drops → phones
  get close code 4410 and reconnect later.

`src/core.ts` is the host-independent logic; `src/node.ts` and `src/worker.ts` are the two hosts.

MIT.
