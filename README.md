> ## ✅ TESTED AND TRANSFERRED
>
> This repository has been consolidated into the canonical account. All code, fixes, tests, and
> documentation now live at:
>
> **→ https://github.com/echoomegaprime/echo-canary-beacon**
>
> - Destination commit: `635b6e5cf01a438b2ef2103303b181d354a3f861`
> - Cert Forge certificate: `cert_a031ba2459392697ad654a9dd2c598fa9ffd6d08` — `PRODUCTION_READY`
>   (evidence Merkle root `cf50803a8d42be6503727e4bb634445f296ca680e272e1e57eed4695dcd36f63`,
>   verify at https://cert-api.echosforge.com/v1/certifications/cert_a031ba2459392697ad654a9dd2c598fa9ffd6d08/verdict)
> - GitHub App Suite conformance: manual receipt at
>   [`.echo/repo-health.md`](https://github.com/echoomegaprime/echo-canary-beacon/blob/main/.echo/repo-health.md)
>   in the destination repo (GitHub App Suite auto-posting affected by build #29466 on this
>   account; this is the documented workaround)
> - Transfer date: 2026-08-12
>
> **Important — this README was wrong.** It describes a "honeypot tracking pixel" tool that was
> never actually deployed. The real product in this repo is a **canary deployment monitor** with
> automatic rollback (routes `/deploy`, `/deployments`, `/history`, cron-driven health checks) —
> a Cloudflare Worker plus a Python FastAPI service on FORGE. The honeypot code was dead,
> unreferenced by `wrangler.toml`, and has been removed; the destination repo's README describes
> the real product. During transfer, the dashboard route (`GET /`) was also found to have no
> authentication, exposing worker names/versions/health data — now fixed. See
> [SECURITY.md in the destination repo](https://github.com/echoomegaprime/echo-canary-beacon/blob/main/SECURITY.md).
>
> This legacy repository is preserved for provenance and is not actively maintained. Do not
> open issues or PRs here — use the destination repository above.

---

# Echo Canary Beacon

Honeypot tracking pixel and canary link server. Deploys invisible tracking beacons in emails and documents to detect unauthorized access, forwarding, or data leaks.

## Architecture

```
Email/Document with embedded beacon
         │
         ▼
┌──────────────────────────────────┐
│  Cloudflare Worker               │
│  ├─ /px/:token  → Tracking pixel │
│  ├─ /doc/:token → Canary link    │
│  ├─ /fp/:token  → Fingerprint    │
│  ├─ /captures   → View results   │
│  └─ /health     → Health check   │
└──────────┬───────────────────────┘
           │
           ▼
     KV (HITS) — 30-day TTL
```

## Features

- **Tracking Pixel** (`/px/:token`) — 1x1 transparent GIF served with no-cache headers. Logs IP, user agent, country, all headers on email open.
- **Canary Link** (`/doc/:token`) — Serves a fake "loading document" page that silently collects deep browser fingerprints (WebGL, Canvas, battery, network, screen, timezone, plugins) before showing "Access Denied."
- **Fingerprint Collection** (`/fp/:token`) — POST endpoint receiving client-side fingerprint data from the canary page.
- **Captures Viewer** (`/captures?key=ADMIN_KEY`) — Authenticated endpoint to view all collected data, sorted by timestamp.
- **Full Header Capture** — Every request logs all HTTP headers for forensic analysis.
- **Cloudflare Geo** — Automatic country detection via `cf-ipcountry` header.

## API Reference

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | None | Health check with total hit count |
| GET | `/px/:token` | None | Tracking pixel (returns 1x1 GIF) |
| GET | `/doc/:token` | None | Canary link (serves fingerprint page) |
| POST | `/fp/:token` | None | Receive fingerprint data from client JS |
| GET | `/captures?key=KEY` | Admin key | View all captured data |

## Setup

```bash
# Deploy
npx wrangler deploy

# Set admin key
echo "your-admin-key" | npx wrangler secret put ADMIN_KEY

# Verify
curl -s https://echo-canary-beacon.bmcii1976.workers.dev/health
```

## Usage

### Email Tracking Pixel
Embed in HTML email:
```html
<img src="https://echo-canary-beacon.bmcii1976.workers.dev/px/investigation-001" width="1" height="1" />
```

### Canary Link
Include in documents or emails:
```
https://echo-canary-beacon.bmcii1976.workers.dev/doc/case-42-leak-test
```

### View Captures
```bash
curl -s "https://echo-canary-beacon.bmcii1976.workers.dev/captures?key=YOUR_KEY"
```

## Tech Stack

- **Runtime**: Cloudflare Workers
- **Storage**: KV (HITS namespace, 30-day TTL per record)
- **Fingerprinting**: WebGL, Canvas, Battery API, Network Info, Navigator properties

## Data Retention

All captured data expires after 30 days (KV `expirationTtl: 86400 * 30`).

## Python runtime

The production FORGE API is maintained in this repository alongside the Worker. See [PYTHON_RUNTIME.md](PYTHON_RUNTIME.md) for its dependencies, fail-closed configuration, tests, and deployment gate.
