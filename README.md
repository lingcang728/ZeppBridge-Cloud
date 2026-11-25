# ZeppBridge Cloud

[中文](README.zh-CN.md)

The site template for ZeppBridge's **Push to your own site** (Settings › Beta lab ›
Personal Agent options). After every sync, ZeppBridge encrypts your data on your computer
and sends it to a site you own. Your phone or a Personal Agent then reads it there with a
read-only key.

- **The site only stores ciphertext.** The data key stays on your computer and inside the
  read-only keys you hand out; the Worker cannot decrypt what it stores.
- **No GPS.** ZeppBridge refuses to push any object that contains coordinates.
- **Missing values stay `null`.** Nothing is filled in or interpolated.
- **Runs anywhere Node runs.** Deploying the site and creating keys works the same on
  Windows, macOS and Linux. The upload itself is done by ZeppBridge (3.2 and later) on every
  platform, so nothing from this repository runs on your computer after setup.

## What's here

| Folder | What it is |
|---|---|
| `worker/` | The Cloudflare Worker. It stores ciphertext and returns it to holders of a read-only key. |
| `uploader/keys.mjs` | Creates your tenant and connection code, and issues or revokes read-only keys. |
| `shared/crypto.mjs` | The encryption format shared by the Worker, `keys.mjs` and ZeppBridge (WebCrypto: AES-GCM, HKDF, ECDH). |
| `tests/` | `npm test` (node:test, offline). |

## Setup

You need Node 20 or later, a Cloudflare account and a domain on Cloudflare. The free
Workers plan is enough.

### 1. Install and sign in

```sh
npm install
npx wrangler login
```

### 2. Create storage

```sh
npx wrangler kv namespace create zeppbridge-cloud
```

Copy the printed `id` into `worker/wrangler.jsonc` in place of `<YOUR_KV_NAMESPACE_ID>`.
If R2 is enabled on your account you can use a bucket instead; the comments in
`wrangler.jsonc` show how.

### 3. Set your domain and deploy

In `worker/wrangler.jsonc`, replace `health.example.com` with `health.<your domain>`. Then:

```sh
npm run worker:deploy
```

### 4. Create your connection code

```sh
node uploader/keys.mjs init
```

It prints one line of JSON with `tenant`, `dk`, `writeKey` and `readKey`.

- **The whole line is the connection code.** Paste it into ZeppBridge (Push to your own
  site › Connection code) together with your site address. ZeppBridge stores it in the
  system credential store.
- **`readKey` is the read-only key** for your phone or Personal Agent.
- Treat all of it like a password: don't save it in a file, commit it or share it. If you
  lose the line before pasting it, run `init` again and use the new one.

### 5. Read your data

Every request carries `Authorization: Bearer <read-only key>` and gets JSON back (gzip).
Start with `GET https://health.<your domain>/v1`, which lists every route.

| Route | Contents |
|---|---|
| `/v1/summary` | One row per local day for recent days; units in `units`, missing values are `null` |
| `/v1/contract` | Units, time zones, sources and missing-value rules |
| `/v1/status` | When ZeppBridge last pushed and last synced with Zepp |
| `/v1/index` | Which days and workouts are stored |
| `/v1/days/<YYYY-MM-DD>`, `/v1/workouts/<id>` | One day, one workout |
| `/v1/profile`, `/v1/context`, `/v1/plan`, `/v1/baselines`, `/v1/data-health` | The same objects your local AI sees through MCP |

## More read-only keys

One key per reader, so you can revoke them one at a time. Both commands read the secrets
from stdin, so they never show up in your shell history:

```sh
echo '{"dk":"…","writeKey":"zbw_…"}' | node uploader/keys.mjs add-reader --label phone
echo '{"writeKey":"zbw_…"}' | node uploader/keys.mjs revoke-reader --label phone
```

Revoking works from the computer where the key was issued: `keys.mjs` remembers each label
and key hash (never the key) in `readers.json`, under `%LOCALAPPDATA%\ZeppBridgeCloud` on
Windows, `~/Library/Application Support/ZeppBridgeCloud` on macOS and
`~/.local/state/zeppbridge-cloud` on Linux.

## Security notes

- Keys are only ever printed to stdout. `keys.mjs` writes the stored records through a
  temporary file that is deleted right away.
- Workers Logs stay off in `wrangler.jsonc`, because they would record the
  `Authorization` header.
- A write key can only put or delete ciphertext under an allow-listed set of paths; it can't
  read anything. Every failed check returns the same `401`.
- Removing the push in ZeppBridge doesn't delete what is already on your site. To wipe it,
  delete the KV namespace or R2 bucket.

## License

MIT
