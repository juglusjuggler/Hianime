# Hianime Mirror Proxy

Full mirror reverse-proxy for **hianime.city**, optimized for Railway deployment with anti-duplicate SEO handling.

## Features

- **Full reverse proxy** — mirrors all pages, assets, APIs, and streams
- **Anti-duplicate content** — rewrites canonical tags, og:url, hreflang, and all internal links to your mirror domain
- **Robots.txt & Sitemap rewriting** — generates proper robots.txt and rewrites sitemap URLs
- **Redirect handling** — rewrites Location headers on 3xx responses
- **Cookie domain rewriting** — cookies work properly on your mirror domain
- **Streaming for binary content** — images, videos, fonts streamed without buffering
- **Compression support** — handles gzip, deflate, and brotli from origin

## Deploy to Railway

1. Push this repo to GitHub
2. Go to [railway.app](https://railway.app) → **New Project** → **Deploy from GitHub repo**
3. Railway auto-detects Node.js and runs `npm start`
4. Set environment variables (optional):
   - `MIRROR_HOST` — your custom domain (auto-detected if not set)
   - `TARGET_HOST` — target site (default: `hianime.city`)
5. Add your custom domain in Railway dashboard → Settings → Domains

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TARGET_HOST` | `hianime.city` | The origin site to mirror |
| `MIRROR_HOST` | *(auto-detect)* | Your mirror domain (e.g. `yourdomain.com`) |
| `PORT` | `3000` | Server port (Railway sets this automatically) |

## Anti-Duplicate Strategy

Google Search Console marks pages as duplicate when canonical/og:url point to a different domain. This proxy fixes that by:

1. **Canonical rewrite** — removes original `<link rel="canonical">` and injects one pointing to your mirror
2. **OG URL rewrite** — updates `<meta property="og:url">` to mirror domain
3. **Hreflang injection** — adds `x-default` hreflang pointing to mirror
4. **Full URL rewrite** — replaces all `https://hianime.city` references in HTML/CSS/JS/JSON/XML
5. **Sitemap rewrite** — all URLs in sitemap.xml point to your mirror
6. **Robots.txt** — generates clean robots.txt with mirror sitemap URL
7. **X-Robots-Tag** — sends `index, follow` header

## Local Development

```bash
npm install
npm start
# Server runs on http://localhost:3000
```