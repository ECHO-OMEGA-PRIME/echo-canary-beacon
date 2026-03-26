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
