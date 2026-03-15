const express = require("express");
const compression = require("compression");
const https = require("https");
const http = require("http");
const { Readable } = require("stream");
const zlib = require("zlib");
const tls = require("tls");

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================
// CONFIGURATION
// ============================================================
const TARGET_HOST = process.env.TARGET_HOST || "hianime.city";
const TARGET_ORIGIN = `https://${TARGET_HOST}`;

// Direct origin IP — bypasses Cloudflare entirely
const ORIGIN_IP = process.env.ORIGIN_IP || "5.182.209.112";

// MIRROR_HOST will be auto-detected from incoming requests if not set
const MIRROR_HOST = process.env.MIRROR_HOST || "";

// Timeout for upstream requests (ms)
const UPSTREAM_TIMEOUT = parseInt(process.env.UPSTREAM_TIMEOUT) || 15000;

app.use(compression());
app.set("trust proxy", true);

// ============================================================
// STRATEGY MANAGEMENT — track which fetch method works
// ============================================================
const strategies = {
  directIP: { ok: true, fails: 0, lastFail: 0 },
  cloudflareDomain: { ok: true, fails: 0, lastFail: 0 },
};

const FAIL_THRESHOLD = 3;
const RECOVERY_MS = 5 * 60 * 1000;

function markStrategyOk(name) {
  strategies[name].ok = true;
  strategies[name].fails = 0;
}

function markStrategyFail(name) {
  strategies[name].fails++;
  strategies[name].lastFail = Date.now();
  if (strategies[name].fails >= FAIL_THRESHOLD) {
    strategies[name].ok = false;
    console.warn(`[strategy] ${name} marked DOWN after ${FAIL_THRESHOLD} consecutive failures`);
  }
}

function isStrategyAvailable(name) {
  const s = strategies[name];
  if (s.ok) return true;
  if (Date.now() - s.lastFail > RECOVERY_MS) {
    console.log(`[strategy] ${name} attempting recovery...`);
    return true;
  }
  return false;
}

// ============================================================
// BROWSER-LIKE USER AGENTS (rotate to avoid fingerprinting)
// ============================================================
const USER_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
];
let uaIndex = 0;
function getNextUA() {
  const ua = USER_AGENTS[uaIndex % USER_AGENTS.length];
  uaIndex++;
  return ua;
}

// ============================================================
// HELPERS
// ============================================================
function getMirrorHost(req) {
  if (MIRROR_HOST) return MIRROR_HOST;
  return req.get("host") || req.hostname;
}

function getMirrorOrigin(req) {
  const proto = req.protocol || "https";
  return `${proto}://${getMirrorHost(req)}`;
}

const STRIP_REQUEST_HEADERS = new Set([
  "cf-connecting-ip", "cf-ipcountry", "cf-ray", "cf-visitor",
  "x-forwarded-for", "x-forwarded-proto", "x-forwarded-host", "x-real-ip",
]);

const STRIP_RESPONSE_HEADERS = new Set([
  "content-security-policy", "content-security-policy-report-only",
  "x-frame-options", "strict-transport-security", "alt-svc",
  "cf-ray", "cf-cache-status", "report-to", "nel", "server",
  "expect-ct", "permissions-policy", "cross-origin-opener-policy",
  "cross-origin-embedder-policy", "cross-origin-resource-policy",
]);

function buildUpstreamHeaders(req) {
  const headers = {};
  for (const [key, value] of Object.entries(req.headers)) {
    const lk = key.toLowerCase();
    if (STRIP_REQUEST_HEADERS.has(lk)) continue;
    if (lk === "host") continue;
    if (lk === "user-agent") continue;
    headers[key] = value;
  }
  headers["host"] = TARGET_HOST;
  headers["user-agent"] = getNextUA();
  headers["accept"] = req.headers["accept"] || "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8";
  headers["accept-language"] = req.headers["accept-language"] || "en-US,en;q=0.9";
  headers["accept-encoding"] = "gzip, deflate, br";
  headers["connection"] = "keep-alive";
  headers["upgrade-insecure-requests"] = "1";
  if (req.headers["referer"]) {
    headers["referer"] = req.headers["referer"]
      .replace(new RegExp(escapeRegex(getMirrorHost(req)), "gi"), TARGET_HOST);
  }
  return headers;
}

function decompressBody(buffer, encoding) {
  if (!encoding) return Promise.resolve(buffer);
  const enc = encoding.toLowerCase().trim();
  return new Promise((resolve, reject) => {
    if (enc === "gzip") zlib.gunzip(buffer, (e, r) => (e ? reject(e) : resolve(r)));
    else if (enc === "deflate") zlib.inflate(buffer, (e, r) => (e ? reject(e) : resolve(r)));
    else if (enc === "br") zlib.brotliDecompress(buffer, (e, r) => (e ? reject(e) : resolve(r)));
    else resolve(buffer);
  });
}

function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// ============================================================
// UPSTREAM FETCHING — direct IP first, fallback to domain
// ============================================================

/**
 * HTTPS request directly to origin IP, bypassing DNS/Cloudflare.
 * TLS SNI set to TARGET_HOST so cert validation works.
 */
function fetchViaDirectIP(path, headers, method, body) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: ORIGIN_IP,
      port: 443,
      path: path,
      method: method,
      headers: { ...headers, host: TARGET_HOST },
      timeout: UPSTREAM_TIMEOUT,
      servername: TARGET_HOST,
      rejectUnauthorized: false,
    };

    const req = https.request(options, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => {
        resolve({
          status: res.statusCode,
          headers: res.headers,
          body: Buffer.concat(chunks),
          strategy: "directIP",
        });
      });
    });

    req.on("timeout", () => {
      req.destroy();
      reject(new Error("Direct IP request timed out"));
    });
    req.on("error", reject);

    if (body && body.length > 0) req.write(body);
    req.end();
  });
}

/**
 * Fetch via domain name (through Cloudflare if enabled).
 */
async function fetchViaDomain(path, headers, method, body) {
  const url = `${TARGET_ORIGIN}${path}`;
  const options = {
    method,
    headers,
    redirect: "manual",
    signal: AbortSignal.timeout(UPSTREAM_TIMEOUT),
  };
  if (body && body.length > 0 && !["GET", "HEAD"].includes(method.toUpperCase())) {
    options.body = body;
  }

  const res = await fetch(url, options);

  const chunks = [];
  if (res.body) {
    const reader = res.body.getReader();
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
    }
  }

  const resHeaders = {};
  for (const [k, v] of res.headers.entries()) {
    resHeaders[k] = v;
  }

  return {
    status: res.status,
    headers: resHeaders,
    body: Buffer.concat(chunks),
    strategy: "cloudflareDomain",
  };
}

/**
 * Detect Cloudflare challenge / block pages
 */
function isCloudflareChallenge(upstreamRes) {
  const status = upstreamRes.status;
  const hasCfRay = !!getHeader(upstreamRes.headers, "cf-ray");
  const server = getHeader(upstreamRes.headers, "server") || "";

  if ((status === 403 || status === 503) && (hasCfRay || server.toLowerCase().includes("cloudflare"))) {
    const bodyStr = upstreamRes.body.toString("utf-8").substring(0, 5000);
    if (
      bodyStr.includes("cf-browser-verification") ||
      bodyStr.includes("challenge-platform") ||
      bodyStr.includes("Just a moment") ||
      bodyStr.includes("Checking your browser") ||
      bodyStr.includes("cf_chl_opt") ||
      bodyStr.includes("Attention Required") ||
      bodyStr.includes("ray ID")
    ) {
      return true;
    }
  }
  return false;
}

/**
 * Case-insensitive header getter for plain objects or Headers
 */
function getHeader(headers, name) {
  if (!headers) return null;
  const lower = name.toLowerCase();
  if (typeof headers === "object" && !headers.get) {
    for (const [k, v] of Object.entries(headers)) {
      if (k.toLowerCase() === lower) return v;
    }
    return null;
  }
  if (headers.get) return headers.get(name);
  return null;
}

/**
 * Main upstream fetch with strategy fallback:
 *   1. Direct IP (bypasses CF completely)
 *   2. Via domain (works if CF allows)
 *   3. Last-resort retry on direct IP
 */
async function fetchFromOrigin(path, headers, method, body) {
  const errors = [];

  // Strategy 1: Direct IP
  if (isStrategyAvailable("directIP")) {
    try {
      const res = await fetchViaDirectIP(path, headers, method, body);
      if (!isCloudflareChallenge(res)) {
        markStrategyOk("directIP");
        return res;
      }
      console.warn("[directIP] Cloudflare challenge on direct IP");
      markStrategyFail("directIP");
    } catch (err) {
      errors.push(`directIP: ${err.message}`);
      markStrategyFail("directIP");
    }
  }

  // Strategy 2: Via domain
  if (isStrategyAvailable("cloudflareDomain")) {
    try {
      const res = await fetchViaDomain(path, headers, method, body);
      if (!isCloudflareChallenge(res)) {
        markStrategyOk("cloudflareDomain");
        return res;
      }
      console.warn("[cloudflareDomain] Cloudflare challenge detected");
      markStrategyFail("cloudflareDomain");
      errors.push("cloudflareDomain: Cloudflare challenge");
    } catch (err) {
      errors.push(`cloudflareDomain: ${err.message}`);
      markStrategyFail("cloudflareDomain");
    }
  }

  // Last-resort: retry direct IP
  try {
    const res = await fetchViaDirectIP(path, headers, method, body);
    if (!isCloudflareChallenge(res)) {
      markStrategyOk("directIP");
      return res;
    }
  } catch (err) {
    errors.push(`directIP-retry: ${err.message}`);
  }

  throw new Error(`All strategies failed: ${errors.join(" | ")}`);
}

// ============================================================
// CONTENT REWRITING
// ============================================================

function rewriteHTML(html, req) {
  const mirrorHost = getMirrorHost(req);
  const mirrorOrigin = getMirrorOrigin(req);
  let out = html;

  // Rewrite WordPress Jetpack CDN URLs: https://i{0-3}.wp.com/hianime.city/path → mirror/path
  out = out.replace(
    new RegExp(`https?://i[0-3]\\.wp\\.com/${escapeRegex(TARGET_HOST)}(/[^"'\\s]*)`, "gi"),
    `${mirrorOrigin}$1`
  );
  // Also handle srcset and data-src variants with wp.com CDN
  out = out.replace(
    new RegExp(`https?://i[0-3]\\.wp\\.com/${escapeRegex(TARGET_HOST)}`, "gi"),
    mirrorOrigin
  );

  // Replace full URLs
  out = out.replace(new RegExp(`https?://${escapeRegex(TARGET_HOST)}`, "gi"), mirrorOrigin);
  // Replace protocol-relative
  out = out.replace(new RegExp(`//${escapeRegex(TARGET_HOST)}`, "gi"), `//${mirrorHost}`);

  // Canonical tag
  out = out.replace(/<link\s+[^>]*rel\s*=\s*["']canonical["'][^>]*\/?>/gi, "");
  const canonicalURL = `${mirrorOrigin}${req.originalUrl}`;
  if (/<head(\s[^>]*)?>/.test(out)) {
    out = out.replace(/(<head(?:\s[^>]*)?>)/i, `$1\n<link rel="canonical" href="${canonicalURL}" />`);
  }

  // OG url
  out = out.replace(
    /<meta\s+[^>]*property\s*=\s*["']og:url["'][^>]*\/?>/gi,
    `<meta property="og:url" content="${canonicalURL}" />`
  );

  // Hreflang
  out = out.replace(/<link\s+[^>]*hreflang\s*=\s*["'][^"']*["'][^>]*\/?>/gi, "");
  if (/<head(\s[^>]*)?>/.test(out)) {
    out = out.replace(
      /(<link\s+rel="canonical"[^>]*\/>)/i,
      `$1\n<link rel="alternate" hreflang="x-default" href="${canonicalURL}" />`
    );
  }

  // Remaining meta content
  out = out.replace(
    new RegExp(`content\\s*=\\s*["']https?://${escapeRegex(TARGET_HOST)}([^"']*)["']`, "gi"),
    `content="${mirrorOrigin}$1"`
  );

  // JSON-escaped URLs in inline scripts: https:\/\/hianime.city → mirror
  const jsonEscapedTarget = `https:\\/\\/${TARGET_HOST}`;
  const jsonEscapedMirror = mirrorOrigin.replace(/\//g, "\\/");
  while (out.includes(jsonEscapedTarget)) {
    out = out.replace(jsonEscapedTarget, jsonEscapedMirror);
  }
  const jsonEscapedTargetHttp = `http:\\/\\/${TARGET_HOST}`;
  while (out.includes(jsonEscapedTargetHttp)) {
    out = out.replace(jsonEscapedTargetHttp, jsonEscapedMirror);
  }

  return out;
}

function rewriteCSS(css, req) {
  const mirrorHost = getMirrorHost(req);
  const mirrorOrigin = getMirrorOrigin(req);
  let out = css;
  // WP CDN
  out = out.replace(new RegExp(`https?://i[0-3]\\.wp\\.com/${escapeRegex(TARGET_HOST)}`, "gi"), mirrorOrigin);
  out = out.replace(new RegExp(`https?://${escapeRegex(TARGET_HOST)}`, "gi"), mirrorOrigin);
  out = out.replace(new RegExp(`//${escapeRegex(TARGET_HOST)}`, "gi"), `//${mirrorHost}`);
  return out;
}

function rewriteJS(js, req) {
  const mirrorHost = getMirrorHost(req);
  const mirrorOrigin = getMirrorOrigin(req);
  let out = js;
  // WP CDN
  out = out.replace(new RegExp(`https?://i[0-3]\\.wp\\.com/${escapeRegex(TARGET_HOST)}`, "gi"), mirrorOrigin);
  out = out.replace(new RegExp(`https?://${escapeRegex(TARGET_HOST)}`, "gi"), mirrorOrigin);
  out = out.replace(new RegExp(`//${escapeRegex(TARGET_HOST)}`, "gi"), `//${mirrorHost}`);
  // JSON-escaped URLs
  const jsonEscapedTarget = `https:\\/\\/${TARGET_HOST}`;
  const jsonEscapedMirror = mirrorOrigin.replace(/\//g, "\\/");
  while (out.includes(jsonEscapedTarget)) {
    out = out.replace(jsonEscapedTarget, jsonEscapedMirror);
  }
  return out;
}

function rewriteJSON(json, req) {
  const mirrorOrigin = getMirrorOrigin(req);
  let out = json;
  // WP CDN
  out = out.replace(new RegExp(`https?://i[0-3]\\.wp\\.com/${escapeRegex(TARGET_HOST)}`, "gi"), mirrorOrigin);
  out = out.replace(new RegExp(`https?://${escapeRegex(TARGET_HOST)}`, "gi"), mirrorOrigin);
  // JSON-escaped URLs
  const jsonEscapedTarget = `https:\\/\\/${TARGET_HOST}`;
  const jsonEscapedMirror = mirrorOrigin.replace(/\//g, "\\/");
  while (out.includes(jsonEscapedTarget)) {
    out = out.replace(jsonEscapedTarget, jsonEscapedMirror);
  }
  return out;
}

function generateRobotsTxt(req) {
  const mirrorOrigin = getMirrorOrigin(req);
  return `User-agent: *\nAllow: /\n\nSitemap: ${mirrorOrigin}/sitemap.xml\n`;
}

function rewriteSitemap(xml, req) {
  const mirrorOrigin = getMirrorOrigin(req);
  return xml.replace(new RegExp(`https?://${escapeRegex(TARGET_HOST)}`, "gi"), mirrorOrigin);
}

function getContentCategory(contentType) {
  if (!contentType) return "other";
  const ct = contentType.toLowerCase();
  if (ct.includes("text/html") || ct.includes("application/xhtml")) return "html";
  if (ct.includes("text/css")) return "css";
  if (ct.includes("javascript") || ct.includes("ecmascript")) return "js";
  if (ct.includes("application/json") || ct.includes("+json")) return "json";
  if (ct.includes("text/xml") || ct.includes("application/xml") || ct.includes("+xml")) return "xml";
  if (ct.includes("text/")) return "text";
  return "other";
}

// ============================================================
// HEALTH CHECK ENDPOINT
// ============================================================
app.get("/_mirror/health", (req, res) => {
  res.json({
    status: "ok",
    target: TARGET_HOST,
    originIP: ORIGIN_IP,
    strategies: {
      directIP: strategies.directIP,
      cloudflareDomain: strategies.cloudflareDomain,
    },
  });
});

// ============================================================
// MAIN PROXY HANDLER
// ============================================================
app.all("*", async (req, res) => {
  try {
    const mirrorOrigin = getMirrorOrigin(req);
    const path = req.originalUrl;

    if (path.startsWith("/_mirror/")) return res.status(404).end();

    // robots.txt
    if (path === "/robots.txt") {
      res.set("Content-Type", "text/plain; charset=utf-8");
      res.set("Cache-Control", "public, max-age=3600");
      return res.send(generateRobotsTxt(req));
    }

    // Collect body
    let reqBody = null;
    if (!["GET", "HEAD"].includes(req.method.toUpperCase())) {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      if (chunks.length > 0) reqBody = Buffer.concat(chunks);
    }

    const upstreamHeaders = buildUpstreamHeaders(req);

    // Fetch with fallback
    const upstreamRes = await fetchFromOrigin(path, upstreamHeaders, req.method, reqBody);

    // Copy response headers
    const resHeaders = upstreamRes.headers;
    for (const [key, value] of Object.entries(resHeaders)) {
      const lk = key.toLowerCase();
      if (STRIP_RESPONSE_HEADERS.has(lk)) continue;
      if (lk === "content-encoding") continue;
      if (lk === "content-length") continue;
      if (lk === "transfer-encoding") continue;

      if (lk === "location") {
        const newLocation = value
          .replace(new RegExp(`https?://${escapeRegex(TARGET_HOST)}`, "gi"), mirrorOrigin)
          .replace(new RegExp(`//${escapeRegex(TARGET_HOST)}`, "gi"), `//${getMirrorHost(req)}`);
        res.set(key, newLocation);
        continue;
      }

      if (lk === "set-cookie") {
        const rewritten = value.replace(
          new RegExp(`domain\\s*=\\s*\\.?${escapeRegex(TARGET_HOST)}`, "gi"),
          `domain=${getMirrorHost(req)}`
        );
        res.append(key, rewritten);
        continue;
      }

      res.set(key, value);
    }

    if (upstreamRes.status >= 300 && upstreamRes.status < 400) {
      return res.status(upstreamRes.status).end();
    }

    res.set("X-Robots-Tag", "index, follow");

    const contentType = getHeader(resHeaders, "content-type") || "";
    const category = getContentCategory(contentType);

    if (category === "other") {
      res.status(upstreamRes.status);
      return res.send(upstreamRes.body);
    }

    // Decompress → rewrite → send
    const contentEncoding = getHeader(resHeaders, "content-encoding");
    let bodyBuffer;
    try {
      bodyBuffer = await decompressBody(upstreamRes.body, contentEncoding);
    } catch {
      bodyBuffer = upstreamRes.body;
    }

    let bodyText = bodyBuffer.toString("utf-8");

    switch (category) {
      case "html": bodyText = rewriteHTML(bodyText, req); break;
      case "css": bodyText = rewriteCSS(bodyText, req); break;
      case "js": bodyText = rewriteJS(bodyText, req); break;
      case "json": bodyText = rewriteJSON(bodyText, req); break;
      case "xml": bodyText = rewriteSitemap(bodyText, req); break;
      case "text":
        bodyText = bodyText.replace(
          new RegExp(`https?://${escapeRegex(TARGET_HOST)}`, "gi"),
          mirrorOrigin
        );
        break;
    }

    res.status(upstreamRes.status);
    res.send(bodyText);
  } catch (err) {
    console.error("Proxy error:", err.message);
    res.status(502).send("Bad Gateway");
  }
});

// ============================================================
// STARTUP PROBE
// ============================================================
async function probeStrategies() {
  console.log("[startup] Probing upstream strategies...");

  try {
    const res = await fetchViaDirectIP("/", { host: TARGET_HOST, "user-agent": getNextUA() }, "HEAD", null);
    if (isCloudflareChallenge(res)) {
      console.log(`[startup] Direct IP → Cloudflare challenge (status ${res.status})`);
      strategies.directIP.ok = false;
    } else {
      console.log(`[startup] Direct IP → OK (status ${res.status})`);
    }
  } catch (err) {
    console.log(`[startup] Direct IP → FAILED (${err.message})`);
    strategies.directIP.ok = false;
  }

  try {
    const res = await fetchViaDomain("/", { host: TARGET_HOST, "user-agent": getNextUA(), accept: "*/*" }, "HEAD", null);
    if (isCloudflareChallenge(res)) {
      console.log(`[startup] Domain → Cloudflare challenge (status ${res.status})`);
      strategies.cloudflareDomain.ok = false;
    } else {
      console.log(`[startup] Domain → OK (status ${res.status})`);
    }
  } catch (err) {
    console.log(`[startup] Domain → FAILED (${err.message})`);
    strategies.cloudflareDomain.ok = false;
  }

  if (!strategies.directIP.ok && !strategies.cloudflareDomain.ok) {
    console.warn("[startup] WARNING: Both strategies currently failing — will retry on each request");
  }
}

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Mirror proxy running on port ${PORT}`);
  console.log(`Target: ${TARGET_ORIGIN} | Origin IP: ${ORIGIN_IP}`);
  if (MIRROR_HOST) {
    console.log(`Mirror host: ${MIRROR_HOST}`);
  } else {
    console.log(`Mirror host: auto-detected from requests`);
  }
  probeStrategies();
});