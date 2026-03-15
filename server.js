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

// Custom logo path (served from /public/hianime.png)
const CUSTOM_LOGO = process.env.CUSTOM_LOGO || "https://pub-b809a12aff9f4b918a309f6bdbd29455.r2.dev/hianime.png";
// Original logo filename pattern to replace
const ORIGINAL_LOGO_PATTERN = process.env.ORIGINAL_LOGO_PATTERN || "9453036c-bed9-4ac2-987c-d354b4bcaafa";

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
// IMUNIFY360 / WEBSHIELD COOKIE JAR
// ============================================================
// Imunify360 WebShield sets cookies (e.g. wsidchk, __imunify_session)
// after a challenge redirect. We store them and send on every request.
const cookieJar = new Map(); // key=cookieName, value=cookieValue
let cookieJarString = ""; // pre-built "name=val; name2=val2" string

function updateCookieJar(setCookieHeaders) {
  if (!setCookieHeaders) return;
  const headers = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];
  for (const sc of headers) {
    // Parse "name=value; Path=...; ..." → extract name=value
    const match = sc.match(/^([^=]+)=([^;]*)/);
    if (match) {
      cookieJar.set(match[1].trim(), match[2].trim());
    }
  }
  // Rebuild the cookie string
  const parts = [];
  for (const [k, v] of cookieJar.entries()) {
    parts.push(`${k}=${v}`);
  }
  cookieJarString = parts.join("; ");
  if (cookieJar.size > 0) {
    console.log(`[cookiejar] Updated: ${cookieJar.size} cookies stored`);
  }
}

function getCookieString() {
  return cookieJarString;
}

/**
 * Detect Imunify360 WebShield challenge redirect.
 * Pattern: 302/301 redirect to /z0f76a...?wsidchk=...
 * or response body containing wsidchk / imunify references
 */
function isImunifyChallenge(upstreamRes) {
  const status = upstreamRes.status;
  const location = getHeader(upstreamRes.headers, "location") || "";
  const server = (getHeader(upstreamRes.headers, "server") || "").toLowerCase();

  // Redirect-based challenge
  if (status >= 300 && status < 400) {
    if (location.includes("wsidchk") || /\/z[0-9a-f]{30,}/.test(location)) {
      return { type: "redirect", location };
    }
  }

  // Body-based challenge (some versions show inline)
  if (status === 403 || status === 503 || status === 200) {
    if (server.includes("openresty") || server.includes("imunify")) {
      const bodyStr = upstreamRes.body.toString("utf-8").substring(0, 5000);
      if (
        bodyStr.includes("wsidchk") ||
        bodyStr.includes("imunify") ||
        bodyStr.includes("__imunify_session") ||
        /\/z[0-9a-f]{30,}/.test(bodyStr)
      ) {
        // Try to extract redirect URL from body
        const urlMatch = bodyStr.match(/(?:href|url|location)[="'\s]*(\/z[0-9a-f]+[^"'\s>]*wsidchk[^"'\s>]*)/i);
        if (urlMatch) {
          return { type: "redirect", location: urlMatch[1] };
        }
        return { type: "block" };
      }
    }
  }

  // 404 with openresty — likely Imunify blocked
  if (status === 404 && server.includes("openresty")) {
    const bodyStr = upstreamRes.body.toString("utf-8").substring(0, 2000);
    if (bodyStr.includes("openresty") || bodyStr.length < 500) {
      return { type: "block" };
    }
  }

  return null;
}

/**
 * Solve Imunify360 challenge: follow the redirect URL to get cookies,
 * then return the cookies so subsequent requests pass.
 */
async function solveImunifyChallenge(challengeLocation, strategy) {
  console.log(`[imunify] Solving challenge: ${challengeLocation}`);

  // Ensure the location is a full path
  let challengePath = challengeLocation;
  if (challengePath.startsWith("http")) {
    try {
      const u = new URL(challengePath);
      challengePath = u.pathname + u.search;
    } catch {
      // use as-is
    }
  }

  const headers = {
    host: TARGET_HOST,
    "user-agent": getNextUA(),
    accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "accept-language": "en-US,en;q=0.9",
    "accept-encoding": "gzip, deflate, br",
    connection: "keep-alive",
    "upgrade-insecure-requests": "1",
    referer: `https://${TARGET_HOST}/`,
  };
  if (getCookieString()) {
    headers["cookie"] = getCookieString();
  }

  let res;
  try {
    if (strategy === "directIP") {
      res = await fetchViaDirectIPRaw(challengePath, headers, "GET", null);
    } else {
      res = await fetchViaDomainRaw(challengePath, headers, "GET", null);
    }
  } catch (err) {
    console.error(`[imunify] Challenge request failed: ${err.message}`);
    return false;
  }

  // Collect cookies from the challenge response
  const setCookies = getSetCookieHeaders(res.headers);
  if (setCookies.length > 0) {
    updateCookieJar(setCookies);
    console.log(`[imunify] Got ${setCookies.length} cookies from challenge`);
  }

  // If the challenge itself redirects again, follow up to 3 hops
  let hops = 0;
  let currentRes = res;
  while (currentRes.status >= 300 && currentRes.status < 400 && hops < 3) {
    const nextLoc = getHeader(currentRes.headers, "location");
    if (!nextLoc) break;

    let nextPath = nextLoc;
    if (nextPath.startsWith("http")) {
      try { nextPath = new URL(nextPath).pathname + new URL(nextPath).search; } catch {}
    }

    console.log(`[imunify] Following redirect hop ${hops + 1}: ${nextPath}`);
    headers["cookie"] = getCookieString();

    try {
      if (strategy === "directIP") {
        currentRes = await fetchViaDirectIPRaw(nextPath, headers, "GET", null);
      } else {
        currentRes = await fetchViaDomainRaw(nextPath, headers, "GET", null);
      }
      const moreCookies = getSetCookieHeaders(currentRes.headers);
      if (moreCookies.length > 0) updateCookieJar(moreCookies);
    } catch (err) {
      console.error(`[imunify] Redirect hop failed: ${err.message}`);
      break;
    }
    hops++;
  }

  console.log(`[imunify] Challenge solved. Cookie jar has ${cookieJar.size} cookies`);
  return cookieJar.size > 0;
}

/**
 * Extract Set-Cookie headers from response headers (handles both
 * single string, array, and raw http headers where it could be joined)
 */
function getSetCookieHeaders(headers) {
  if (!headers) return [];
  // node http.IncomingMessage stores set-cookie as array
  const sc = headers["set-cookie"];
  if (!sc) return [];
  if (Array.isArray(sc)) return sc;
  return [sc];
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
    if (lk === "cookie") continue; // we manage cookies ourselves
    headers[key] = value;
  }
  headers["host"] = TARGET_HOST;
  headers["user-agent"] = getNextUA();
  headers["accept"] = req.headers["accept"] || "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8";
  headers["accept-language"] = req.headers["accept-language"] || "en-US,en;q=0.9";
  headers["accept-encoding"] = "gzip, deflate, br";
  headers["connection"] = "keep-alive";
  headers["upgrade-insecure-requests"] = "1";
  // Attach stored cookies (Imunify360 wsidchk etc.)
  if (getCookieString()) {
    headers["cookie"] = getCookieString();
  }
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
/**
 * Raw direct IP fetch — returns result without Imunify handling.
 * Used internally by the challenge solver.
 */
function fetchViaDirectIPRaw(path, headers, method, body) {
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
 * Direct IP fetch with Imunify360 challenge auto-solving.
 */
async function fetchViaDirectIP(path, headers, method, body) {
  // Ensure cookies are attached
  if (getCookieString() && !headers["cookie"]) {
    headers["cookie"] = getCookieString();
  }

  const res = await fetchViaDirectIPRaw(path, headers, method, body);

  // Collect any cookies
  const sc = getSetCookieHeaders(res.headers);
  if (sc.length > 0) updateCookieJar(sc);

  // Check for Imunify360 challenge
  const imunify = isImunifyChallenge(res);
  if (imunify) {
    console.log(`[directIP] Imunify360 challenge detected (${imunify.type})`);
    if (imunify.type === "redirect" && imunify.location) {
      const solved = await solveImunifyChallenge(imunify.location, "directIP");
      if (solved) {
        // Retry the original request with the new cookies
        headers["cookie"] = getCookieString();
        const retry = await fetchViaDirectIPRaw(path, headers, method, body);
        const sc2 = getSetCookieHeaders(retry.headers);
        if (sc2.length > 0) updateCookieJar(sc2);
        // Check if still challenged
        const still = isImunifyChallenge(retry);
        if (!still) return retry;
        console.warn("[directIP] Still challenged after solving — giving up on this strategy");
      }
    }
    // Return the challenge response so fallback strategies can try
    return res;
  }

  return res;
}

/**
 * Fetch via domain name (through Cloudflare if enabled).
 */
/**
 * Raw domain fetch — no Imunify handling.
 */
async function fetchViaDomainRaw(path, headers, method, body) {
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

  // Collect all set-cookie headers properly
  const resHeaders = {};
  for (const [k, v] of res.headers.entries()) {
    resHeaders[k] = v;
  }
  // fetch() merges set-cookie; get them via getSetCookie if available
  if (res.headers.getSetCookie) {
    const setCookies = res.headers.getSetCookie();
    if (setCookies.length > 0) {
      resHeaders["set-cookie"] = setCookies;
    }
  }

  return {
    status: res.status,
    headers: resHeaders,
    body: Buffer.concat(chunks),
    strategy: "cloudflareDomain",
  };
}

/**
 * Domain fetch with Imunify360 challenge auto-solving.
 */
async function fetchViaDomain(path, headers, method, body) {
  if (getCookieString() && !headers["cookie"]) {
    headers["cookie"] = getCookieString();
  }

  const res = await fetchViaDomainRaw(path, headers, method, body);

  const sc = getSetCookieHeaders(res.headers);
  if (sc.length > 0) updateCookieJar(sc);

  const imunify = isImunifyChallenge(res);
  if (imunify) {
    console.log(`[domain] Imunify360 challenge detected (${imunify.type})`);
    if (imunify.type === "redirect" && imunify.location) {
      const solved = await solveImunifyChallenge(imunify.location, "cloudflareDomain");
      if (solved) {
        headers["cookie"] = getCookieString();
        const retry = await fetchViaDomainRaw(path, headers, method, body);
        const sc2 = getSetCookieHeaders(retry.headers);
        if (sc2.length > 0) updateCookieJar(sc2);
        const still = isImunifyChallenge(retry);
        if (!still) return retry;
        console.warn("[domain] Still challenged after solving");
      }
    }
    return res;
  }

  return res;
}

/**
 * Detect Cloudflare challenge / block pages
 */
function isCloudflareChallenge(upstreamRes) {
  // First check if it's an Imunify360 challenge (not Cloudflare)
  if (isImunifyChallenge(upstreamRes)) return false; // handled separately

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
      if (!isCloudflareChallenge(res) && !isImunifyChallenge(res)) {
        markStrategyOk("directIP");
        return res;
      }
      if (isCloudflareChallenge(res)) {
        console.warn("[directIP] Cloudflare challenge on direct IP");
      }
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
      if (!isCloudflareChallenge(res) && !isImunifyChallenge(res)) {
        markStrategyOk("cloudflareDomain");
        return res;
      }
      if (isCloudflareChallenge(res)) {
        console.warn("[cloudflareDomain] Cloudflare challenge detected");
      }
      markStrategyFail("cloudflareDomain");
      errors.push("cloudflareDomain: challenge");
    } catch (err) {
      errors.push(`cloudflareDomain: ${err.message}`);
      markStrategyFail("cloudflareDomain");
    }
  }

  // Last-resort: retry direct IP with current cookies
  try {
    headers["cookie"] = getCookieString();
    const res = await fetchViaDirectIP(path, headers, method, body);
    if (!isCloudflareChallenge(res) && !isImunifyChallenge(res)) {
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

  // ---- Replace original logo with custom logo ----
  // Match the logo <img> inside <h1 class="logos"> or <span class="logos">
  out = out.replace(
    /(<(?:h1|span)\s+class="logos">\s*<a[^>]*>\s*<img[^>]*?)\s*src="[^"]*"/gi,
    `$1 src="${CUSTOM_LOGO}"`
  );
  // Also catch any <img> with the original logo filename anywhere
  if (ORIGINAL_LOGO_PATTERN) {
    out = out.replace(
      new RegExp(`(<img[^>]*?)src="[^"]*${escapeRegex(ORIGINAL_LOGO_PATTERN)}[^"]*"`, "gi"),
      `$1src="${CUSTOM_LOGO}"`
    );
  }
  // Replace JS variables dmlogo1/dmlogo2 that override the logo on theme toggle
  out = out.replace(
    /var\s+dmlogo1\s*=\s*'[^']*'/gi,
    `var dmlogo1 = '${CUSTOM_LOGO}'`
  );
  out = out.replace(
    /var\s+dmlogo2\s*=\s*'[^']*'/gi,
    `var dmlogo2 = '${CUSTOM_LOGO}'`
  );

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

// Serve custom static assets (logo, etc.) from /public/
const path_module = require("path");
app.use("/public", express.static(path_module.join(__dirname, "public"), {
  maxAge: "7d",
  immutable: true,
}));

app.get("/_mirror/health", (req, res) => {
  res.json({
    status: "ok",
    target: TARGET_HOST,
    originIP: ORIGIN_IP,
    strategies: {
      directIP: strategies.directIP,
      cloudflareDomain: strategies.cloudflareDomain,
    },
    cookieJar: {
      count: cookieJar.size,
      keys: [...cookieJar.keys()],
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

  // Use GET instead of HEAD — Imunify360 often blocks HEAD requests
  const probeHeaders = {
    host: TARGET_HOST,
    "user-agent": getNextUA(),
    accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "accept-language": "en-US,en;q=0.9",
    "accept-encoding": "gzip, deflate, br",
    connection: "keep-alive",
    "upgrade-insecure-requests": "1",
  };

  try {
    // fetchViaDirectIP now auto-solves Imunify challenges
    const res = await fetchViaDirectIP("/", { ...probeHeaders }, "GET", null);
    const imunify = isImunifyChallenge(res);
    if (isCloudflareChallenge(res)) {
      console.log(`[startup] Direct IP → Cloudflare challenge (status ${res.status})`);
      strategies.directIP.ok = false;
    } else if (imunify) {
      console.log(`[startup] Direct IP → Imunify360 challenge persists (status ${res.status})`);
      // Don't mark as down — it may work on next try with cookies
    } else {
      console.log(`[startup] Direct IP → OK (status ${res.status})`);
    }
  } catch (err) {
    console.log(`[startup] Direct IP → FAILED (${err.message})`);
    strategies.directIP.ok = false;
  }

  try {
    const res = await fetchViaDomain("/", { ...probeHeaders }, "GET", null);
    const imunify = isImunifyChallenge(res);
    if (isCloudflareChallenge(res)) {
      console.log(`[startup] Domain → Cloudflare challenge (status ${res.status})`);
      strategies.cloudflareDomain.ok = false;
    } else if (imunify) {
      console.log(`[startup] Domain → Imunify360 challenge persists (status ${res.status})`);
    } else {
      console.log(`[startup] Domain → OK (status ${res.status})`);
    }
  } catch (err) {
    console.log(`[startup] Domain → FAILED (${err.message})`);
    strategies.cloudflareDomain.ok = false;
  }

  console.log(`[startup] Cookie jar: ${cookieJar.size} cookies stored`);
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