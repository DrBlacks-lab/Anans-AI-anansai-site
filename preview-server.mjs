import http from "node:http";
import { readFile, stat } from "node:fs/promises";
import { extname, join, normalize, resolve } from "node:path";
import { createHmac, timingSafeEqual, scryptSync, randomUUID } from "node:crypto";

const PORT = Number(process.env.PORT || 3000);
const ROOT = resolve(process.cwd());
const SESSION_NAME = "anans_preview_session";
const SESSION_TTL_SECONDS = 60 * 60 * 8;
const WINDOW_MS = 10 * 60 * 1000;
const LOCK_MS = 15 * 60 * 1000;
const MAX_FAILURES = 5;
const failures = new Map();

for (const key of ["SESSION_SECRET", "ADMIN_USERNAME", "ADMIN_PASSWORD_SCRYPT"]) {
  if (!process.env[key]) {
    console.error(`Missing required environment variable: ${key}`);
    process.exit(1);
  }
}

function parseGuests() {
  try {
    const parsed = JSON.parse(process.env.GUEST_ACCOUNTS_JSON || "{}");
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch {
    console.error("GUEST_ACCOUNTS_JSON must be a JSON object");
    process.exit(1);
  }
}
const GUESTS = parseGuests();
const ADMIN_SESSION_VERSION = Number(process.env.ADMIN_SESSION_VERSION || "1");

const safeUser = value => String(value || "").trim().toLowerCase().slice(0, 80);
const b64url = input => Buffer.from(input).toString("base64url");
const sign = value => createHmac("sha256", process.env.SESSION_SECRET).update(value).digest("base64url");
function isExpired(iso) {
  if (!iso) return false;
  const t = Date.parse(iso);
  return !Number.isFinite(t) || t <= Date.now();
}
function guestRecord(username) {
  const g = GUESTS[username];
  if (!g || typeof g !== "object" || g.enabled === false || isExpired(g.expires_at)) return null;
  return g;
}
function makeSession(username, role, version, absoluteExpiry = null) {
  const now = Math.floor(Date.now() / 1000);
  let exp = now + SESSION_TTL_SECONDS;
  if (absoluteExpiry) {
    const guestExp = Math.floor(Date.parse(absoluteExpiry) / 1000);
    if (Number.isFinite(guestExp)) exp = Math.min(exp, guestExp);
  }
  const payload = b64url(JSON.stringify({ sub: username, role, ver: version, sid: randomUUID(), exp }));
  return `${payload}.${sign(payload)}`;
}
function readSession(req) {
  const raw = req.headers.cookie || "";
  const entry = raw.split(";").map(x => x.trim()).find(x => x.startsWith(`${SESSION_NAME}=`));
  if (!entry) return null;
  const value = decodeURIComponent(entry.slice(SESSION_NAME.length + 1));
  const [payload, signature] = value.split(".");
  if (!payload || !signature) return null;
  const expected = Buffer.from(sign(payload));
  const received = Buffer.from(signature);
  if (expected.length !== received.length || !timingSafeEqual(expected, received)) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (!data.exp || data.exp < Math.floor(Date.now() / 1000)) return null;
    if (data.role === "admin") {
      if (data.sub !== safeUser(process.env.ADMIN_USERNAME) || Number(data.ver) !== ADMIN_SESSION_VERSION) return null;
      return data;
    }
    if (data.role === "guest") {
      const g = guestRecord(data.sub);
      if (!g || Number(data.ver) !== Number(g.session_version || 1)) return null;
      return data;
    }
    return null;
  } catch { return null; }
}

function verifyScrypt(password, encoded) {
  if (typeof encoded !== "string" || !encoded.includes("$")) return false;
  const [saltHex, expectedHex] = encoded.split("$", 2);
  try {
    const actual = scryptSync(String(password), Buffer.from(saltHex, "hex"), 64, { N: 16384, r: 8, p: 1 });
    const expected = Buffer.from(expectedHex, "hex");
    return actual.length === expected.length && timingSafeEqual(actual, expected);
  } catch { return false; }
}

function clientIp(req) {
  const forwarded = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim();
  return (forwarded || req.socket.remoteAddress || "unknown").slice(0, 96);
}
const authKey = (req, username) => `${clientIp(req)}|${safeUser(username)}`;
function rateState(key) {
  const now = Date.now();
  const state = failures.get(key);
  if (!state) return { count: 0, first: now, lockedUntil: 0 };
  if (state.lockedUntil > now) return state;
  if (now - state.first > WINDOW_MS) {
    failures.delete(key);
    return { count: 0, first: now, lockedUntil: 0 };
  }
  return state;
}
function recordFailure(key) {
  const now = Date.now();
  const state = rateState(key);
  state.count += 1;
  if (state.count >= MAX_FAILURES) state.lockedUntil = now + LOCK_MS;
  failures.set(key, state);
}
const clearFailures = key => failures.delete(key);

const CSP = "default-src 'none'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; img-src 'self' data:; style-src 'self'; script-src 'none'; connect-src 'none'; font-src 'none'; media-src 'none'; manifest-src 'none'; upgrade-insecure-requests";
function commonHeaders(extra = {}) {
  return {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Strict-Transport-Security": "max-age=31536000",
    "Cache-Control": "no-store, private",
    "X-Robots-Tag": "noindex, nofollow, noarchive",
    ...extra
  };
}
function send(res, status, body, headers = {}, headOnly = false) {
  res.writeHead(status, commonHeaders(headers));
  if (headOnly) return res.end();
  res.end(body);
}
function redirect(res, location, cookie = null) {
  const headers = { Location: location };
  if (cookie) headers["Set-Cookie"] = cookie;
  send(res, 303, "", headers);
}
const sessionCookie = (value, maxAge = SESSION_TTL_SECONDS) => `${SESSION_NAME}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${Math.max(0, maxAge)}`;
const clearCookie = () => sessionCookie("", 0);
const esc = value => String(value ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]));

const loginPage = (error = "") => `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow,noarchive"><title>ANANS Village — Restricted Preview</title><link rel="stylesheet" href="/auth.css"></head><body><main><div class="mark">ANANS</div><h1>Restricted village preview</h1><p>Testing surface. Access is limited to the Founder/admin account and explicitly provisioned guest accounts.</p>${error ? `<p class="error">${esc(error)}</p>` : ""}<form method="post" action="/login" autocomplete="on"><label for="username">Username</label><input id="username" name="username" required autocomplete="username" maxlength="80"><label for="password">Password</label><input id="password" name="password" type="password" required autocomplete="current-password" maxlength="256"><button type="submit">Enter restricted preview</button></form><p class="small">Authentication grants preview access only. It does not grant deployment, publication, spending, or other consequential authority.</p></main></body></html>`;

function adminPage(session) {
  const rows = Object.entries(GUESTS).map(([name, g]) => {
    const active = Boolean(guestRecord(name));
    return `<li><strong>${esc(name)}</strong> · <span class="${active ? "ok" : "hold"}">${active ? "enabled" : "disabled/expired"}</span><br><span class="meta">expires: ${esc(g?.expires_at || "not set")} · session_version: ${esc(g?.session_version || 1)}</span></li>`;
  }).join("") || "<li>No guest accounts configured.</li>";
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>ANANS Preview Admin</title><link rel="stylesheet" href="/auth.css"></head><body><main><div class="mark">ANANS</div><h1>Preview administration</h1><p>Signed in as <strong>${esc(session.sub)}</strong>. This surface exposes preview-account state only.</p><ul class="guest-list">${rows}</ul><p class="small">Guest provisioning remains explicit and configuration-backed. There is no self-registration. Incrementing a guest's <code>session_version</code>, disabling it, or expiring it invalidates outstanding sessions on the next request.</p><div class="row"><a class="button" href="/">Open village preview</a><a class="button" href="/logout">Sign out</a></div></main></body></html>`;
}

const MIME = {
  ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml",
  ".png": "image/png", ".webp": "image/webp", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
  ".ico": "image/x-icon", ".xml": "application/xml; charset=utf-8", ".txt": "text/plain; charset=utf-8"
};
const DENY_FILES = new Set(["package.json", "package-lock.json", "preview-server.mjs", "CNAME", ".nojekyll"]);

async function serveNamedFile(res, relative, headOnly = false) {
  if (relative === "assets/anans-village.webp") {
    try {
      const parts = await Promise.all([0,1,2,3].map(i => readFile(resolve(join(ROOT, `assets/anans-village.webp.b64.part-${String(i).padStart(2, "0")}`)), "utf8")));
      const data = Buffer.from(parts.join("").trim(), "base64");
      if (data.length < 100000) throw new Error("image decode failed");
      return send(res, 200, data, { "Content-Type": "image/webp", "Content-Length": String(data.length) }, headOnly);
    } catch {
      return send(res, 500, "Preview image unavailable", { "Content-Type": "text/plain; charset=utf-8" }, headOnly);
    }
  }
  const filePath = resolve(join(ROOT, relative));
  if (!filePath.startsWith(ROOT + "/") && filePath !== ROOT) return send(res, 404, "Not found", { "Content-Type": "text/plain; charset=utf-8" }, headOnly);
  const ext = extname(filePath).toLowerCase();
  if (!MIME[ext]) return send(res, 404, "Not found", { "Content-Type": "text/plain; charset=utf-8" }, headOnly);
  try {
    const info = await stat(filePath);
    if (!info.isFile()) throw new Error("not file");
    const data = await readFile(filePath);
    return send(res, 200, data, { "Content-Type": MIME[ext], "Content-Length": String(data.length) }, headOnly);
  } catch {
    return send(res, 404, "Not found", { "Content-Type": "text/plain; charset=utf-8" }, headOnly);
  }
}

async function serveStatic(req, res, session) {
  const headOnly = req.method === "HEAD";
  if (!headOnly && req.method !== "GET") return send(res, 405, "Method not allowed", { Allow: "GET, HEAD", "Content-Type": "text/plain; charset=utf-8" });
  let pathname;
  try { pathname = decodeURIComponent(new URL(req.url, "http://preview.local").pathname); }
  catch { return send(res, 400, "Bad request", { "Content-Type": "text/plain; charset=utf-8" }); }
  if (pathname === "/") pathname = "/index.html";
  const clean = normalize(pathname).replace(/^(\.\.(\/|\\|$))+/, "");
  const relative = clean.replace(/^[/\\]+/, "");
  if (!relative || DENY_FILES.has(relative) || relative.startsWith(".git") || relative.includes("..")) return send(res, 404, "Not found", { "Content-Type": "text/plain; charset=utf-8" }, headOnly);
  if (relative === "index.html") {
    try {
      const raw = await readFile(resolve(join(ROOT, "index.html")), "utf8");
      const adminNav = session.role === "admin" ? '<a class="admin-nav" href="/admin">Admin</a>' : "";
      const html = raw.replace("<!--ADMIN_NAV-->", adminNav);
      return send(res, 200, html, { "Content-Type": "text/html; charset=utf-8", "Content-Length": String(Buffer.byteLength(html)) }, headOnly);
    } catch {
      return send(res, 500, "Preview unavailable", { "Content-Type": "text/plain; charset=utf-8" }, headOnly);
    }
  }
  return serveNamedFile(res, relative, headOnly);
}

async function readForm(req) {
  return await new Promise((resolveForm, rejectForm) => {
    let body = "";
    req.setEncoding("utf8");
    req.on("data", chunk => {
      body += chunk;
      if (body.length > 8192) { rejectForm(new Error("form too large")); req.destroy(); }
    });
    req.on("end", () => resolveForm(Object.fromEntries(new URLSearchParams(body).entries())));
    req.on("error", rejectForm);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://preview.local");
  const session = readSession(req);
  const headOnly = req.method === "HEAD";
  if (url.pathname === "/health") return send(res, 200, "ok", { "Content-Type": "text/plain; charset=utf-8" }, headOnly);
  if (url.pathname === "/robots.txt") return send(res, 200, "User-agent: *\nDisallow: /\n", { "Content-Type": "text/plain; charset=utf-8" }, headOnly);
  if (url.pathname === "/auth.css") return serveNamedFile(res, "auth.css", headOnly);
  if (url.pathname === "/login" && (req.method === "GET" || req.method === "HEAD")) {
    if (session) return redirect(res, "/");
    return send(res, 200, loginPage(), { "Content-Type": "text/html; charset=utf-8" }, headOnly);
  }
  if (url.pathname === "/login" && req.method === "POST") {
    try {
      const { username = "", password = "" } = await readForm(req);
      const user = safeUser(username);
      const key = authKey(req, user);
      const state = rateState(key);
      if (state.lockedUntil > Date.now()) {
        return send(res, 429, loginPage("Too many failed attempts. Try again later."), { "Content-Type": "text/html; charset=utf-8", "Retry-After": String(Math.ceil((state.lockedUntil - Date.now()) / 1000)) });
      }
      let role = null;
      let version = 1;
      let expiresAt = null;
      if (user === safeUser(process.env.ADMIN_USERNAME) && verifyScrypt(password, process.env.ADMIN_PASSWORD_SCRYPT)) {
        role = "admin"; version = ADMIN_SESSION_VERSION;
      } else {
        const g = guestRecord(user);
        if (g && verifyScrypt(password, g.password_scrypt)) {
          role = "guest"; version = Number(g.session_version || 1); expiresAt = g.expires_at || null;
        }
      }
      if (!role) {
        recordFailure(key);
        return send(res, 401, loginPage("Invalid username or password."), { "Content-Type": "text/html; charset=utf-8" });
      }
      clearFailures(key);
      return redirect(res, "/", sessionCookie(makeSession(user, role, version, expiresAt)));
    } catch {
      return send(res, 400, loginPage("Unable to process sign-in."), { "Content-Type": "text/html; charset=utf-8" });
    }
  }
  if (url.pathname === "/logout") return redirect(res, "/login", clearCookie());
  if (url.pathname === "/auth/status") {
    if (!session) return send(res, 401, JSON.stringify({ authenticated: false }), { "Content-Type": "application/json" });
    return send(res, 200, JSON.stringify({ authenticated: true, role: session.role, username: session.sub }), { "Content-Type": "application/json" });
  }
  if (url.pathname === "/admin") {
    if (!session) return redirect(res, "/login");
    if (session.role !== "admin") return send(res, 403, "Forbidden", { "Content-Type": "text/plain; charset=utf-8" });
    return send(res, 200, adminPage(session), { "Content-Type": "text/html; charset=utf-8" });
  }
  if (!session) return redirect(res, "/login");
  return serveStatic(req, res, session);
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`ANANS restricted preview listening on ${PORT}`);
  console.log(`Guest accounts configured: ${Object.keys(GUESTS).length}`);
});
