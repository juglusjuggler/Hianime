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
// PROCESS-LEVEL ERROR HANDLING — Prevent Crashes
// ============================================================
process.on("uncaughtException", (err) => {
  console.error(`[FATAL] Uncaught Exception: ${err.message}`);
  console.error(err.stack);
  // Don't exit — try to keep running
});

process.on("unhandledRejection", (reason, promise) => {
  console.error(`[FATAL] Unhandled Rejection at:`, promise, `reason:`, reason);
  // Don't exit — try to keep running
});

// Graceful shutdown handling
let isShuttingDown = false;
function gracefulShutdown(signal) {
  if (isShuttingDown) return;
  isShuttingDown = true;
  console.log(`[shutdown] Received ${signal}, shutting down gracefully...`);
  
  // Stop accepting new connections
  if (server) {
    server.close(() => {
      console.log("[shutdown] Server closed");
      process.exit(0);
    });
  }
  
  // Force exit after 10 seconds
  setTimeout(() => {
    console.error("[shutdown] Forced exit after timeout");
    process.exit(1);
  }, 10000);
}

process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT", () => gracefulShutdown("SIGINT"));

let server = null; // Will be assigned when app.listen() is called

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
const UPSTREAM_TIMEOUT = parseInt(process.env.UPSTREAM_TIMEOUT) || 30000;

// Create HTTPS agents — will be recreated if they fail
function createAgent() {
  return new https.Agent({
    keepAlive: true,
    keepAliveMsecs: 15000,
    maxSockets: 100,
    maxFreeSockets: 20,
    timeout: UPSTREAM_TIMEOUT,
    scheduling: "fifo", // Better for consistent connections
  });
}

let directIPAgent = createAgent();
let domainAgent = createAgent();

// Agent refresh — recreate agents when connections fail
let agentRefreshCount = 0;
function refreshAgents() {
  agentRefreshCount++;
  console.log(`[agent] Refreshing HTTPS agents (refresh #${agentRefreshCount})`);
  
  // Destroy old agents
  try {
    directIPAgent.destroy();
    domainAgent.destroy();
  } catch (e) {
    console.warn(`[agent] Error destroying old agents: ${e.message}`);
  }
  
  // Create new agents
  directIPAgent = createAgent();
  domainAgent = createAgent();
}

// Refresh agents periodically to prevent stale connections
setInterval(() => {
  // Only refresh if idle (not during active failures)
  if (strategies && strategies.directIP.ok && strategies.cloudflareDomain.ok) {
    refreshAgents();
  }
}, 10 * 60 * 1000); // Every 10 minutes

// Custom logo path (served from /public/hianime.png)
const CUSTOM_LOGO = process.env.CUSTOM_LOGO || "https://pub-b809a12aff9f4b918a309f6bdbd29455.r2.dev/hianime.png";
// Original logo filename pattern to replace
const ORIGINAL_LOGO_PATTERN = process.env.ORIGINAL_LOGO_PATTERN || "9453036c-bed9-4ac2-987c-d354b4bcaafa";

// ============================================================
// AD / MALWARE DOMAIN BLOCKLIST — stripped from upstream HTML
// ============================================================
const AD_DOMAINS = [
  "effectivegatecpm.com",
  "profitablegatecpm.com",
  "highperformancegatecpm.com",
  "effectiveperformancenetwork.com",
  "storageimagedisplay.com",
  "onclickalgo.com",
  "onclickperformance.com",
  "onclickmax.com",
  "clickadu.com",
  "clickadilla.com",
  "pushame.com",
  "pushnami.com",
  "pushprofit.com",
  "push-notifications.click",
  "trafficjunky.com",
  "exoclick.com",
  "exosrv.com",
  "juicyads.com",
  "hilltopads.net",
  "hilltopads.com",
  "a-ads.com",
  "ad-maven.com",
  "admaven.com",
  "adsterra.com",
  "adsterratools.com",
  "propellerads.com",
  "propellerclick.com",
  "popcash.net",
  "popads.net",
  "popunder.net",
  "richpush.com",
  "pushground.com",
  "evadav.com",
  "galaksion.com",
  "monetag.com",
  "surfrival.com",
  "bongacams.com",
  "chaturbate.com",
  "livejasmin.com",
  "cam4.com",
  "stripchat.com",
  "1xbet.com",
  "mostbet.com",
  "melbet.com",
  "linebet.com",
  "betway.com",
  "bet365.com",
  "betfury.com",
  "stake.com",
  "rollercoin.com",
  "notifpush.com",
  "pushwhy.com",
  "winr.mobi",
  "cpx.to",
  "acint.net",
  "tsyndicate.com",
  "realsrv.com",
  "disqusads.com",
  "adnxs.com",
  "doubleclick.net",
  "googlesyndication.com",
  "adsco.re",
  "adzilla.com",
  "adzilla.io",
];

// Build regex for matching ad domains in src/href attributes
const AD_DOMAIN_PATTERN = AD_DOMAINS.map(d => escapeRegex(d)).join("|");
const AD_DOMAIN_REGEX = new RegExp(AD_DOMAIN_PATTERN, "i");

/**
 * Strip all ad-related content from HTML response.
 * This runs BEFORE other rewriting to remove ads at the source.
 */
function stripAds(html) {
  let out = html;

  // 1. Remove <script> tags loading from ad domains
  //    Matches: <script ...src="...effectivegatecpm.com..."...>...</script>
  //    and self-closing: <script ...src="...effectivegatecpm.com...".../>
  out = out.replace(
    new RegExp(`<script[^>]*\\bsrc\\s*=\\s*["'][^"']*(?:${AD_DOMAIN_PATTERN})[^"']*["'][^>]*>[\\s\\S]*?<\\/script>`, "gi"),
    "<!-- ad removed -->"
  );
  out = out.replace(
    new RegExp(`<script[^>]*\\bsrc\\s*=\\s*["'][^"']*(?:${AD_DOMAIN_PATTERN})[^"']*["'][^>]*\\/?>`, "gi"),
    "<!-- ad removed -->"
  );

  // 2. Remove <script> tags with data-cfasync that load invoke.js (common ad pattern)
  out = out.replace(
    /<script[^>]*data-cfasync\s*=\s*["']false["'][^>]*src\s*=\s*["'][^"']*invoke\.js["'][^>]*>[\s\S]*?<\/script>/gi,
    "<!-- ad removed -->"
  );
  out = out.replace(
    /<script[^>]*src\s*=\s*["'][^"']*invoke\.js["'][^>]*data-cfasync\s*=\s*["']false["'][^>]*>[\s\S]*?<\/script>/gi,
    "<!-- ad removed -->"
  );

  // 3. Remove entire <div class="kln">...</div> ad wrapper blocks
  //    These contain ad containers; use greedy but bounded matching
  out = out.replace(
    /<div\s+class\s*=\s*["']kln["'][^>]*>[\s\S]*?<\/div>\s*(?:<\/div>\s*)*(?=<(?:div|section|main|article|footer|header|nav|aside|script|link|!--|\/body|\/html)|\s*$)/gi,
    "<!-- ad block removed -->"
  );

  // 4. Remove ad container divs with long hex hash IDs/classes
  //    Pattern: id="container-[32hex]" or class="container-[32hex]..."
  out = out.replace(
    /<div\s+[^>]*(?:id|class)\s*=\s*["']container-[a-f0-9]{20,}[^"']*["'][^>]*>[\s\S]*?<\/div>/gi,
    "<!-- ad container removed -->"
  );

  // 5. Remove <iframe> tags from ad domains
  out = out.replace(
    new RegExp(`<iframe[^>]*\\bsrc\\s*=\\s*["'][^"']*(?:${AD_DOMAIN_PATTERN})[^"']*["'][^>]*>[\\s\\S]*?<\\/iframe>`, "gi"),
    "<!-- ad iframe removed -->"
  );
  out = out.replace(
    new RegExp(`<iframe[^>]*\\bsrc\\s*=\\s*["'][^"']*(?:${AD_DOMAIN_PATTERN})[^"']*["'][^>]*\\/?>`, "gi"),
    "<!-- ad iframe removed -->"
  );

  // 6. Remove <a> tags pointing to ad domains (ad click links)
  out = out.replace(
    new RegExp(`<a[^>]*\\bhref\\s*=\\s*["'][^"']*(?:${AD_DOMAIN_PATTERN})[^"']*["'][^>]*>[\\s\\S]*?<\\/a>`, "gi"),
    ""
  );

  // 7. Remove inline <script> blocks that reference ad domains
  //    e.g., <script>...effectivegatecpm.com...</script>
  out = out.replace(
    new RegExp(`<script(?:\\s[^>]*)?>([\\s\\S]*?)<\\/script>`, "gi"),
    function(match, scriptContent) {
      if (AD_DOMAIN_REGEX.test(scriptContent)) {
        return "<!-- ad script removed -->";
      }
      // Also catch common ad loader patterns
      if (/\binvoke\.js\b/.test(scriptContent) && /container-[a-f0-9]{20,}/.test(scriptContent)) {
        return "<!-- ad loader removed -->";
      }
      return match;
    }
  );

  // 8. Remove <link> (preload/prefetch) for ad domains
  out = out.replace(
    new RegExp(`<link[^>]*\\bhref\\s*=\\s*["'][^"']*(?:${AD_DOMAIN_PATTERN})[^"']*["'][^>]*\\/?>`, "gi"),
    "<!-- ad link removed -->"
  );

  // 9. Remove <img> loading from ad image CDNs
  out = out.replace(
    new RegExp(`<img[^>]*\\bsrc\\s*=\\s*["'][^"']*(?:storageimagedisplay\\.com)[^"']*["'][^>]*\\/?>`, "gi"),
    "<!-- ad image removed -->"
  );

  // 10. Remove background-image styles referencing ad CDNs
  out = out.replace(
    new RegExp(`background-image\\s*:\\s*url\\([^)]*(?:storageimagedisplay\\.com)[^)]*\\)`, "gi"),
    "background-image: none"
  );

  // 11. Clean up leftover nested empty ad divs and orphaned ad wrappers
  //     After removing inner content, we may have empty <div class="kln"></div>
  for (let i = 0; i < 5; i++) {
    out = out.replace(/<div[^>]*>\s*(?:<!--[^>]*-->)*\s*<\/div>/g, "");
  }

  return out;
}

/**
 * Strip ad references from JavaScript files.
 */
function stripAdsFromJS(js) {
  let out = js;
  // Remove any string literals containing ad domains
  for (const domain of AD_DOMAINS) {
    // Replace URL strings pointing to ad domains with empty string
    out = out.replace(
      new RegExp(`(["'\`])https?:\\/\\/[^"'\`]*${escapeRegex(domain)}[^"'\`]*\\1`, "gi"),
      "''"
    );
    out = out.replace(
      new RegExp(`(["'\`])\\/\\/[^"'\`]*${escapeRegex(domain)}[^"'\`]*\\1`, "gi"),
      "''"
    );
  }
  return out;
}

/**
 * Strip ad references from CSS files.
 */
function stripAdsFromCSS(css) {
  let out = css;
  // Remove @import rules loading from ad domains
  out = out.replace(
    new RegExp(`@import\\s+(?:url\\()?[^;]*(?:${AD_DOMAIN_PATTERN})[^;]*;`, "gi"),
    "/* ad import removed */"
  );
  // Remove background-image referencing ad CDNs
  out = out.replace(
    new RegExp(`background(?:-image)?\\s*:[^;]*(?:storageimagedisplay\\.com)[^;]*;`, "gi"),
    "background-image: none;"
  );
  return out;
}

app.use(compression());
app.set("trust proxy", true);

// ============================================================
// HTTPS REDIRECT — prevent ISP HTTP interception
// ============================================================
app.use((req, res, next) => {
  if (req.headers["x-forwarded-proto"] === "http") {
    return res.redirect(301, `https://${req.headers.host}${req.url}`);
  }
  next();
});

// ============================================================
// SECURITY HEADERS — block ISP ad injection / XSS / clickjacking
// ============================================================
function setSecurityHeaders(res, req) {
  const mirrorHost = getMirrorHost(req);

  // Content Security Policy — primary defense against ISP injection.
  // Blocks scripts/iframes/objects from unauthorized domains.
  const csp = [
    "default-src 'self' https://" + mirrorHost,
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' blob: https://" + mirrorHost
      + " https://" + TARGET_HOST
      + " https://*.google.com https://*.googleapis.com https://*.gstatic.com"
      + " https://*.google-analytics.com https://*.googletagmanager.com"
      + " https://cdnjs.cloudflare.com https://*.cloudflare.com"
      + " https://*.jsdelivr.net https://*.r2.dev",
    "worker-src 'self' blob:",
    "style-src 'self' 'unsafe-inline' https://" + mirrorHost
      + " https://" + TARGET_HOST
      + " https://fonts.googleapis.com https://cdnjs.cloudflare.com"
      + " https://*.cloudflare.com https://*.jsdelivr.net",
    "img-src 'self' data: blob: https: http:",
    "font-src 'self' data: https://fonts.gstatic.com https://" + TARGET_HOST
      + " https://" + mirrorHost + " https://cdnjs.cloudflare.com",
    "connect-src 'self' https://" + mirrorHost + " https://" + TARGET_HOST
      + " wss://" + mirrorHost + " wss://" + TARGET_HOST + " https://*.r2.dev"
      + " https://*.google-analytics.com https://*.googleapis.com https://*.googletagmanager.com",
    "media-src 'self' https: blob: data:",
    "frame-src 'self' https://" + mirrorHost + " https:",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self' https://" + mirrorHost,
    "frame-ancestors 'self'",
    "upgrade-insecure-requests"
  ].join("; ");

  res.set("Content-Security-Policy", csp);
  res.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");
  res.set("X-Content-Type-Options", "nosniff");
  res.set("X-Frame-Options", "SAMEORIGIN");
  res.set("X-XSS-Protection", "1; mode=block");
  res.set("Referrer-Policy", "strict-origin-when-cross-origin");
  res.set("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=()");
  res.set("Cross-Origin-Opener-Policy", "same-origin");
}

/**
 * Generate anti-injection HTML code (CSP meta tag + MutationObserver script)
 * injected into every HTML page as defense-in-depth against ISP tampering.
 */
function getAntiInjectionCode(mirrorHost) {
  // CSP meta tag — survives even if HTTP headers are stripped by ISP proxies
  const metaCSP = [
    "default-src 'self' https://" + mirrorHost,
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' blob: https://" + mirrorHost
      + " https://" + TARGET_HOST
      + " https://*.google.com https://*.googleapis.com https://*.gstatic.com"
      + " https://*.google-analytics.com https://*.googletagmanager.com"
      + " https://cdnjs.cloudflare.com https://*.cloudflare.com"
      + " https://*.jsdelivr.net https://*.r2.dev",
    "worker-src 'self' blob:",
    "style-src 'self' 'unsafe-inline' https://" + mirrorHost
      + " https://" + TARGET_HOST
      + " https://fonts.googleapis.com https://cdnjs.cloudflare.com"
      + " https://*.cloudflare.com https://*.jsdelivr.net",
    "img-src 'self' data: blob: https: http:",
    "font-src 'self' data: https://fonts.gstatic.com https://" + TARGET_HOST
      + " https://" + mirrorHost + " https://cdnjs.cloudflare.com",
    "connect-src 'self' https://" + mirrorHost + " https://" + TARGET_HOST
      + " wss://" + mirrorHost + " wss://" + TARGET_HOST + " https://*.r2.dev"
      + " https://*.google-analytics.com https://*.googleapis.com https://*.googletagmanager.com",
    "media-src 'self' https: blob: data:",
    "frame-src 'self' https://" + mirrorHost + " https:",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self' https://" + mirrorHost,
    "upgrade-insecure-requests"
  ].join("; ");

  return '<meta http-equiv="Content-Security-Policy" content="' + metaCSP + '">'
    + '<script>(function(){"use strict";'
    // Blocked ad domains list
    + 'var B=["effectivegatecpm.com","profitablegatecpm.com","highperformancegatecpm.com","effectiveperformancenetwork.com","storageimagedisplay.com","onclickalgo.com","onclickperformance.com","onclickmax.com","clickadu.com","clickadilla.com","pushame.com","pushnami.com","pushprofit.com","trafficjunky.com","exoclick.com","exosrv.com","juicyads.com","hilltopads.net","hilltopads.com","a-ads.com","ad-maven.com","admaven.com","adsterra.com","adsterratools.com","propellerads.com","propellerclick.com","popcash.net","popads.net","popunder.net","richpush.com","pushground.com","evadav.com","galaksion.com","monetag.com","surfrival.com","notifpush.com","pushwhy.com","winr.mobi","cpx.to","acint.net","tsyndicate.com","realsrv.com","adsco.re","googlesyndication.com","adzilla.com","adzilla.io"];'
    // Allowed hostnames — everything else is treated as injected
    + 'var A=["' + mirrorHost + '","' + TARGET_HOST + '","fonts.googleapis.com","fonts.gstatic.com","cdnjs.cloudflare.com","www.google.com","www.gstatic.com","ajax.googleapis.com","www.google-analytics.com","www.googletagmanager.com"];'
    // Check if URL is from a blocked ad domain
    + 'function isAd(s){if(!s)return false;try{var h=(new URL(s,location.href)).hostname.toLowerCase();for(var i=0;i<B.length;i++){if(h===B[i]||h.endsWith("."+B[i]))return true;}}catch(e){}return false;}'
    // Check if URL is allowed
    + 'function ok(s){if(!s)return true;if(isAd(s))return false;try{var u=new URL(s,location.href);'
    + 'if(u.origin===location.origin)return true;'
    + 'for(var i=0;i<A.length;i++){if(u.hostname===A[i]||u.hostname.endsWith("."+A[i]))return true;}'
    + 'if(u.hostname.endsWith(".r2.dev")||u.hostname.endsWith(".cloudflare.com")||u.hostname.endsWith(".jsdelivr.net"))return true;'
    + '}catch(e){return true;}return false;}'
    // Check if an element or its children contain ad content
    + 'function isAdEl(n){if(!n||n.nodeType!==1)return false;'
    + 'var c=n.className||"";if(typeof c==="string"&&(c==="kln"||/container-[a-f0-9]{20,}/.test(c)))return true;'
    + 'var id=n.id||"";if(/container-[a-f0-9]{20,}/.test(id))return true;'
    + 'if(n.tagName==="SCRIPT"){var s=n.src||"";if(isAd(s))return true;if(s&&/invoke\\.js/.test(s))return true;'
    + 'var t=n.textContent||"";for(var i=0;i<B.length;i++){if(t.indexOf(B[i])!==-1)return true;}}return false;}'
    // Remove an ad element and log it
    + 'function kill(n){try{n.remove();}catch(e){}}'
    // MutationObserver — removes ad elements in real time
    + 'var mo=new MutationObserver(function(ms){for(var i=0;i<ms.length;i++){'
    + 'var ns=ms[i].addedNodes;for(var j=0;j<ns.length;j++){var n=ns[j];'
    + 'if(n.nodeType!==1)continue;'
    + 'if(isAdEl(n)){kill(n);continue;}'
    + 'var t=n.tagName;'
    + 'if((t==="IFRAME"||t==="OBJECT"||t==="EMBED")&&!ok(n.src||n.data)){kill(n);continue;}'
    + 'if(t==="SCRIPT"&&n.src&&!ok(n.src)){kill(n);continue;}'
    + 'if(t==="LINK"&&n.href&&isAd(n.href)){kill(n);continue;}'
    + 'if(n.querySelectorAll){var ads=n.querySelectorAll("[class*=\\"container-\\"],iframe,object,embed,script[src],div.kln");'
    + 'for(var k=0;k<ads.length;k++){if(isAdEl(ads[k])||!ok(ads[k].src||ads[k].data||""))kill(ads[k]);}}'
    + '}}});'
    + 'if(document.documentElement)mo.observe(document.documentElement,{childList:true,subtree:true});'
    + 'else document.addEventListener("DOMContentLoaded",function(){mo.observe(document.documentElement,{childList:true,subtree:true});});'
    // Block unauthorized popups and window.open
    + 'var wo=window.open;window.open=function(u){if(u&&(isAd(u)||!ok(u)))return null;return wo.apply(window,arguments);};'
    // Intercept createElement to block ad script creation
    + 'var ce=document.createElement.bind(document);document.createElement=function(tag){'
    + 'var el=ce(tag);if(tag.toLowerCase()==="script"){'
    + 'var origSet=Object.getOwnPropertyDescriptor(HTMLScriptElement.prototype,"src")||Object.getOwnPropertyDescriptor(el.__proto__,"src");'
    + 'if(origSet&&origSet.set){Object.defineProperty(el,"src",{get:function(){return this.getAttribute("src")||"";},set:function(v){if(isAd(v)){return;}origSet.set.call(this,v);},configurable:true});}}'
    + 'return el;};'
    // Clean existing ad elements on DOMContentLoaded
    + 'function cleanAll(){'
    + 'document.querySelectorAll("div.kln").forEach(function(e){kill(e);});'
    + 'document.querySelectorAll("[class*=\\"container-\\"]").forEach(function(e){if(/container-[a-f0-9]{20,}/.test(e.className))kill(e);});'
    + 'document.querySelectorAll("iframe,object,embed").forEach(function(e){if(!ok(e.src||e.data||""))kill(e);});'
    + 'document.querySelectorAll("script[src]").forEach(function(e){if(isAd(e.src)||!ok(e.src))kill(e);});'
    + '}'
    + 'document.addEventListener("DOMContentLoaded",cleanAll);'
    + 'setTimeout(cleanAll,500);setTimeout(cleanAll,1500);setTimeout(cleanAll,3000);'
    + '})();</script>';
}

// ============================================================
// STRATEGY MANAGEMENT — track which fetch method works
// ============================================================
const strategies = {
  directIP: { ok: true, fails: 0, lastFail: 0, consecutiveSuccess: 0 },
  cloudflareDomain: { ok: true, fails: 0, lastFail: 0, consecutiveSuccess: 0 },
};

const FAIL_THRESHOLD = 3;
const RECOVERY_MS = 30 * 1000; // Reduced from 5 minutes to 30 seconds for faster recovery
const SUCCESS_RESET_THRESHOLD = 2; // Reset fail count after 2 consecutive successes

function markStrategyOk(name) {
  strategies[name].ok = true;
  strategies[name].consecutiveSuccess++;
  
  // Reset fail count after enough consecutive successes
  if (strategies[name].consecutiveSuccess >= SUCCESS_RESET_THRESHOLD) {
    strategies[name].fails = 0;
    strategies[name].consecutiveSuccess = 0;
  }
}

function markStrategyFail(name) {
  strategies[name].fails++;
  strategies[name].consecutiveSuccess = 0;
  strategies[name].lastFail = Date.now();
  
  if (strategies[name].fails >= FAIL_THRESHOLD) {
    strategies[name].ok = false;
    console.warn(`[strategy] ${name} marked DOWN after ${FAIL_THRESHOLD} consecutive failures`);
    
    // Refresh agents when strategy fails — connection might be stale
    refreshAgents();
  }
}

function isStrategyAvailable(name) {
  const s = strategies[name];
  if (s.ok) return true;
  if (Date.now() - s.lastFail > RECOVERY_MS) {
    console.log(`[strategy] ${name} attempting recovery after ${Math.round((Date.now() - s.lastFail) / 1000)}s...`);
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
      agent: directIPAgent,
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
      res.on("error", (err) => {
        console.error(`[directIP] Response error: ${err.message}`);
        reject(err);
      });
    });

    req.on("timeout", () => {
      req.destroy();
      reject(new Error("Direct IP request timed out"));
    });
    
    req.on("error", (err) => {
      // Handle specific socket errors
      if (err.code === "ECONNRESET" || err.code === "ECONNREFUSED" || err.code === "ETIMEDOUT" || err.code === "EPIPE") {
        console.warn(`[directIP] Socket error (${err.code}), may need agent refresh`);
      }
      reject(err);
    });

    // Handle socket-level issues
    req.on("socket", (socket) => {
      socket.on("error", (err) => {
        console.warn(`[directIP] Socket error: ${err.message}`);
      });
    });

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
function fetchViaDomainRaw(path, headers, method, body) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(`${TARGET_ORIGIN}${path}`);
    const options = {
      hostname: urlObj.hostname,
      port: 443,
      path: urlObj.pathname + urlObj.search,
      method: method,
      headers: { ...headers, host: TARGET_HOST },
      timeout: UPSTREAM_TIMEOUT,
      agent: domainAgent,
    };

    const req = https.request(options, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => {
        resolve({
          status: res.statusCode,
          headers: res.headers,
          body: Buffer.concat(chunks),
          strategy: "cloudflareDomain",
        });
      });
      res.on("error", (err) => {
        console.error(`[domain] Response error: ${err.message}`);
        reject(err);
      });
    });

    req.on("timeout", () => {
      req.destroy();
      reject(new Error("Domain request timed out"));
    });
    
    req.on("error", (err) => {
      // Handle specific socket errors
      if (err.code === "ECONNRESET" || err.code === "ECONNREFUSED" || err.code === "ETIMEDOUT" || err.code === "EPIPE") {
        console.warn(`[domain] Socket error (${err.code}), may need agent refresh`);
      }
      reject(err);
    });

    // Handle socket-level issues
    req.on("socket", (socket) => {
      socket.on("error", (err) => {
        console.warn(`[domain] Socket error: ${err.message}`);
      });
    });

    if (body && body.length > 0 && !["GET", "HEAD"].includes(method.toUpperCase())) {
      req.write(body);
    }
    req.end();
  });
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
  // Strip all ad content from upstream HTML FIRST
  let out = stripAds(html);

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

  // Anti-injection defenses (CSP meta tag + MutationObserver script)
  const antiInjection = getAntiInjectionCode(mirrorHost);
  out = out.replace(/(<head(?:\s[^>]*)?>)/i, `$1\n${antiInjection}`);

  // Google Search Console verification
  out = out.replace(/(<head(?:\s[^>]*)?>)/i, `$1\n<meta name="google-site-verification" content="qfWtPpNc4-iQ0DF9op95XatgoHHzyXf6U6nyjcVZygA" />`);

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
  let out = stripAdsFromCSS(css);
  // WP CDN
  out = out.replace(new RegExp(`https?://i[0-3]\\.wp\\.com/${escapeRegex(TARGET_HOST)}`, "gi"), mirrorOrigin);
  out = out.replace(new RegExp(`https?://${escapeRegex(TARGET_HOST)}`, "gi"), mirrorOrigin);
  out = out.replace(new RegExp(`//${escapeRegex(TARGET_HOST)}`, "gi"), `//${mirrorHost}`);
  return out;
}

function rewriteJS(js, req) {
  const mirrorHost = getMirrorHost(req);
  const mirrorOrigin = getMirrorOrigin(req);
  let out = stripAdsFromJS(js);
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
  const mirrorHost = getMirrorHost(req);
  const mirrorOrigin = getMirrorOrigin(req);
  let out = xml;
  // Replace full URLs
  out = out.replace(new RegExp(`https?://${escapeRegex(TARGET_HOST)}`, "gi"), mirrorOrigin);
  // Replace protocol-relative URLs (e.g. //hianime.city in XSL href)
  out = out.replace(new RegExp(`//${escapeRegex(TARGET_HOST)}`, "gi"), `//${mirrorHost}`);
  return out;
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
      setSecurityHeaders(res, req);
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

    // Set security headers AFTER upstream headers (so they aren't overwritten)
    setSecurityHeaders(res, req);

    const contentType = getHeader(resHeaders, "content-type") || "";
    const category = getContentCategory(contentType);

    // Reset error count on success
    global.proxyErrorCount = 0;

    if (category === "other") {
      res.status(upstreamRes.status);
      return res.send(upstreamRes.body);
    }

    // Decompress → rewrite → send
    const contentEncoding = getHeader(resHeaders, "content-encoding");
    let bodyBuffer;
    try {
      bodyBuffer = await decompressBody(upstreamRes.body, contentEncoding);
    } catch (decompErr) {
      console.warn(`[decompress] Failed (${contentEncoding}): ${decompErr.message}, using raw body`);
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
    console.error(`Proxy error [${req.method} ${req.originalUrl}]:`, err.message);

    // Track consecutive proxy errors for agent refresh
    if (!global.proxyErrorCount) global.proxyErrorCount = 0;
    global.proxyErrorCount++;
    
    // Refresh agents if we're seeing repeated failures
    if (global.proxyErrorCount >= 5) {
      console.warn(`[recovery] ${global.proxyErrorCount} consecutive errors — refreshing agents`);
      refreshAgents();
      global.proxyErrorCount = 0;
    }

    // Retry once with a small delay
    try {
      await new Promise(r => setTimeout(r, 1000));
      console.log(`[retry] Retrying ${req.method} ${req.originalUrl}...`);

      // Reset strategies for retry attempt — more aggressive recovery
      if (!strategies.directIP.ok) {
        strategies.directIP.ok = true;
        strategies.directIP.fails = 0;
      }
      if (!strategies.cloudflareDomain.ok) {
        strategies.cloudflareDomain.ok = true;
        strategies.cloudflareDomain.fails = 0;
      }

      const retryHeaders = buildUpstreamHeaders(req);
      const retryRes = await fetchFromOrigin(req.originalUrl, retryHeaders, req.method, reqBody || null);

      // Copy response headers (same logic)
      const retryResHeaders = retryRes.headers;
      for (const [key, value] of Object.entries(retryResHeaders)) {
        const lk = key.toLowerCase();
        if (STRIP_RESPONSE_HEADERS.has(lk)) continue;
        if (lk === "content-encoding" || lk === "content-length" || lk === "transfer-encoding") continue;
        if (lk === "location") {
          const newLocation = value
            .replace(new RegExp(`https?://${escapeRegex(TARGET_HOST)}`, "gi"), getMirrorOrigin(req))
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

      if (retryRes.status >= 300 && retryRes.status < 400) {
        return res.status(retryRes.status).end();
      }

      res.set("X-Robots-Tag", "index, follow");
      setSecurityHeaders(res, req);
      const retryContentType = getHeader(retryResHeaders, "content-type") || "";
      const retryCategory = getContentCategory(retryContentType);
      if (retryCategory === "other") {
        global.proxyErrorCount = 0; // Reset error count on success
        res.status(retryRes.status);
        return res.send(retryRes.body);
      }
      const retryEncoding = getHeader(retryResHeaders, "content-encoding");
      let retryBody;
      try { retryBody = await decompressBody(retryRes.body, retryEncoding); } catch { retryBody = retryRes.body; }
      let retryText = retryBody.toString("utf-8");
      switch (retryCategory) {
        case "html": retryText = rewriteHTML(retryText, req); break;
        case "css": retryText = rewriteCSS(retryText, req); break;
        case "js": retryText = rewriteJS(retryText, req); break;
        case "json": retryText = rewriteJSON(retryText, req); break;
        case "xml": retryText = rewriteSitemap(retryText, req); break;
        case "text":
          retryText = retryText.replace(new RegExp(`https?://${escapeRegex(TARGET_HOST)}`, "gi"), getMirrorOrigin(req));
          break;
      }
      global.proxyErrorCount = 0; // Reset error count on success
      res.status(retryRes.status);
      return res.send(retryText);
    } catch (retryErr) {
      console.error(`[retry] Also failed: ${retryErr.message}`);
    }

    // Trigger a background probe if both retries failed
    console.log("[recovery] Triggering background probe after failed request...");
    probeStrategies().catch(() => {});

    res.status(502).send(`<!DOCTYPE html><html><head><title>Bad Gateway</title><meta http-equiv="refresh" content="5"></head><body style="font-family:sans-serif;text-align:center;padding:60px"><h1>502 Bad Gateway</h1><p>Mirror proxy could not reach upstream server. Auto-retrying in 5 seconds...</p><p style="color:#888;font-size:12px">${new Date().toISOString()}</p></body></html>`);
  }
});

// ============================================================
// STARTUP PROBE & PERIODIC HEALTH CHECK
// ============================================================
async function probeStrategies() {
  if (isShuttingDown) return;
  
  console.log("[probe] Probing upstream strategies...");

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

  let directIPOk = false;
  let domainOk = false;

  try {
    // fetchViaDirectIP now auto-solves Imunify challenges
    const res = await fetchViaDirectIP("/", { ...probeHeaders }, "GET", null);
    const imunify = isImunifyChallenge(res);
    if (isCloudflareChallenge(res)) {
      console.log(`[probe] Direct IP → Cloudflare challenge (status ${res.status})`);
      strategies.directIP.ok = false;
    } else if (imunify) {
      console.log(`[probe] Direct IP → Imunify360 challenge persists (status ${res.status})`);
      // Don't mark as down — it may work on next try with cookies
    } else {
      console.log(`[probe] Direct IP → OK (status ${res.status})`);
      directIPOk = true;
      strategies.directIP.ok = true;
      strategies.directIP.fails = 0;
    }
  } catch (err) {
    console.log(`[probe] Direct IP → FAILED (${err.message})`);
    strategies.directIP.ok = false;
  }

  try {
    const res = await fetchViaDomain("/", { ...probeHeaders }, "GET", null);
    const imunify = isImunifyChallenge(res);
    if (isCloudflareChallenge(res)) {
      console.log(`[probe] Domain → Cloudflare challenge (status ${res.status})`);
      strategies.cloudflareDomain.ok = false;
    } else if (imunify) {
      console.log(`[probe] Domain → Imunify360 challenge persists (status ${res.status})`);
    } else {
      console.log(`[probe] Domain → OK (status ${res.status})`);
      domainOk = true;
      strategies.cloudflareDomain.ok = true;
      strategies.cloudflareDomain.fails = 0;
    }
  } catch (err) {
    console.log(`[probe] Domain → FAILED (${err.message})`);
    strategies.cloudflareDomain.ok = false;
  }

  console.log(`[probe] Cookie jar: ${cookieJar.size} cookies stored`);
  
  if (!strategies.directIP.ok && !strategies.cloudflareDomain.ok) {
    console.warn("[probe] WARNING: Both strategies currently failing — refreshing agents and will retry");
    refreshAgents();
  }
  
  return { directIPOk, domainOk };
}

// Periodic health check — run every 60 seconds to detect upstream recovery
let healthCheckInterval = null;
function startPeriodicHealthCheck() {
  if (healthCheckInterval) return;
  
  healthCheckInterval = setInterval(async () => {
    if (isShuttingDown) return;
    
    // Only run probe if at least one strategy is failing
    if (!strategies.directIP.ok || !strategies.cloudflareDomain.ok) {
      console.log("[healthcheck] Running periodic probe due to strategy failure...");
      await probeStrategies();
    }
  }, 60 * 1000); // Every 60 seconds
  
  console.log("[healthcheck] Periodic health check enabled (every 60s when strategies fail)");
}

// Also run a less frequent probe even when healthy to refresh cookies
setInterval(async () => {
  if (isShuttingDown) return;
  console.log("[healthcheck] Running scheduled upstream probe...");
  await probeStrategies();
}, 5 * 60 * 1000); // Every 5 minutes

server = app.listen(PORT, "0.0.0.0", () => {
  console.log(`Mirror proxy running on port ${PORT}`);
  console.log(`Target: ${TARGET_ORIGIN} | Origin IP: ${ORIGIN_IP}`);
  if (MIRROR_HOST) {
    console.log(`Mirror host: ${MIRROR_HOST}`);
  } else {
    console.log(`Mirror host: auto-detected from requests`);
  }
  console.log(`Recovery timeout: ${RECOVERY_MS / 1000}s | Fail threshold: ${FAIL_THRESHOLD}`);
  probeStrategies().then(() => {
    startPeriodicHealthCheck();
  });
});