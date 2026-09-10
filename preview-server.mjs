import http from "node:http";
import { readFile, stat } from "node:fs/promises";
import { extname, join, normalize, resolve } from "node:path";
import { createHmac, timingSafeEqual, scryptSync } from "node:crypto";

const PORT = Number(process.env.PORT || 3000);
const ROOT = resolve(process.cwd());
const SESSION_NAME = "anans_preview_session";
const SESSION_TTL_SECONDS = 60 * 60 * 8;

const required = ["SESSION_SECRET", "ADMIN_USERNAME", "ADMIN_PASSWORD_SCRYPT"];
for (const key of required) {
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

function b64url(input) {
  return Buffer.from(input).toString("base64url");
}
function sign(value) {
  return createHmac("sha256", process.env.SESSION_SECRET).update(value).digest("base64url");
}
function makeSession(username, role) {
  const payload = b64url(JSON.stringify({
    sub: username,
    role,
    exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS
  }));
  return `${payload}.${sign(payload)}`;
}
function readSession(req) {
  const raw = req.headers.cookie || "";
  const pairs = raw.split(";").map(x => x.trim());
  const entry = pairs.find(x => x.startsWith(`${SESSION_NAME}=`));
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
    if (!["admin", "guest"].includes(data.role)) return null;
    return data;
  } catch {
    return null;
  }
}

function verifyScrypt(password, encoded) {
  if (typeof encoded !== "string" || !encoded.includes("$")) return false;
  const [saltHex, expectedHex] = encoded.split("$", 2);
  try {
    const actual = scryptSync(password, Buffer.from(saltHex, "hex"), 64, { N: 16384, r: 8, p: 1 });
    const expected = Buffer.from(expectedHex, "hex");
    return actual.length === expected.length && timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

function commonHeaders(extra = {}) {
  return {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Cache-Control": "no-store, private",
    ...extra
  };
}
function send(res, status, body, headers = {}) {
  res.writeHead(status, commonHeaders(headers));
  res.end(body);
}
function redirect(res, location, cookie = null) {
  const headers = { Location: location };
  if (cookie) headers["Set-Cookie"] = cookie;
  send(res, 303, "", headers);
}
function sessionCookie(value) {
  return `${SESSION_NAME}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_TTL_SECONDS}`;
}
function clearCookie() {
  return `${SESSION_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

const loginPage = (error = "") => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow,noarchive">
<title>ANANS Village — Restricted Preview</title>
<style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#07110d;color:#f6f0df;font-family:system-ui,sans-serif}
main{width:min(430px,calc(100% - 2rem));padding:2rem;border:1px solid #6f5b2d;background:#0d1914;box-shadow:0 2rem 5rem #0008}
h1{margin:.2rem 0 .6rem;font-size:1.8rem}p{color:#bec9c1;line-height:1.55}.mark{letter-spacing:.18em;font-weight:800;color:#e7bb58}
label{display:block;margin:1rem 0 .35rem}input{width:100%;padding:.8rem;border:1px solid #637066;background:#07110d;color:#fff;border-radius:.35rem}
button{width:100%;margin-top:1.2rem;padding:.85rem;border:1px solid #e7bb58;background:#e7bb58;color:#111;font-weight:800;border-radius:.35rem;cursor:pointer}
.error{border-left:3px solid #d46a58;padding:.65rem .8rem;background:#301512;color:#ffd7cf}.small{font-size:.82rem}
</style></head><body><main>
<div class="mark">ANANS</div><h1>Restricted village preview</h1>
<p>Testing surface. Access is limited to the Founder/admin account and explicitly provisioned guest accounts.</p>
${error ? `<p class="error">${error}</p>` : ""}
<form method="post" action="/login" autocomplete="on">
<label for="username">Username</label><input id="username" name="username" required autocomplete="username">
<label for="password">Password</label><input id="password" name="password" type="password" required autocomplete="current-password">
<button type="submit">Enter restricted preview</button>
</form>
<p class="small">Authentication does not grant deployment, publication, spending, or other consequential authority.</p>
</main></body></html>`;

const deniedPage = `<!doctype html><meta charset="utf-8"><meta name="robots" content="noindex,nofollow">
<title>Forbidden</title><body style="font-family:system-ui;background:#0b1511;color:#eee;padding:2rem">
<h1>403 — Admin only</h1><p>This function is restricted to the admin role.</p><p><a href="/" style="color:#f1c65e">Return to preview</a></p></body>`;

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".webp": "image/webp",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".ico": "image/x-icon",
  ".xml": "application/xml; charset=utf-8",
  ".txt": "text/plain; charset=utf-8"
};
const DENY_FILES = new Set(["package.json", "preview-server.mjs", "CNAME", ".nojekyll"]);

async function serveStatic(req, res) {
  let pathname;
  try {
    pathname = decodeURIComponent(new URL(req.url, "http://preview.local").pathname);
  } catch {
    return send(res, 400, "Bad request", { "Content-Type": "text/plain; charset=utf-8" });
  }
  if (pathname === "/") pathname = "/index.html";
  const clean = normalize(pathname).replace(/^(\.\.(\/|\\|$))+/, "");
  const relative = clean.replace(/^[/\\]+/, "");
  if (!relative || DENY_FILES.has(relative) || relative.startsWith(".git") || relative.includes("..")) {
    return send(res, 404, "Not found", { "Content-Type": "text/plain; charset=utf-8" });
  }
  const filePath = resolve(join(ROOT, relative));
  if (!filePath.startsWith(ROOT + "/") && filePath !== ROOT) {
    return send(res, 404, "Not found", { "Content-Type": "text/plain; charset=utf-8" });
  }
  const ext = extname(filePath).toLowerCase();
  if (!MIME[ext]) return send(res, 404, "Not found", { "Content-Type": "text/plain; charset=utf-8" });
  try {
    const info = await stat(filePath);
    if (!info.isFile()) throw new Error("not file");
    const data = await readFile(filePath);
    send(res, 200, data, {
      "Content-Type": MIME[ext],
      "Content-Length": String(data.length),
      "X-Robots-Tag": "noindex, nofollow, noarchive"
    });
  } catch {
    send(res, 404, "Not found", { "Content-Type": "text/plain; charset=utf-8" });
  }
}

async function readForm(req) {
  return await new Promise((resolveForm, rejectForm) => {
    let body = "";
    req.setEncoding("utf8");
    req.on("data", chunk => {
      body += chunk;
      if (body.length > 8192) {
        rejectForm(new Error("form too large"));
        req.destroy();
      }
    });
    req.on("end", () => {
      const params = new URLSearchParams(body);
      resolveForm(Object.fromEntries(params.entries()));
    });
    req.on("error", rejectForm);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://preview.local");
  const session = readSession(req);

  if (url.pathname === "/health") {
    return send(res, 200, "ok", { "Content-Type": "text/plain; charset=utf-8" });
  }
  if (url.pathname === "/robots.txt") {
    return send(res, 200, "User-agent: *\nDisallow: /\n", { "Content-Type": "text/plain; charset=utf-8" });
  }
  if (url.pathname === "/login" && req.method === "GET") {
    if (session) return redirect(res, "/");
    return send(res, 200, loginPage(), { "Content-Type": "text/html; charset=utf-8", "X-Robots-Tag": "noindex, nofollow, noarchive" });
  }
  if (url.pathname === "/login" && req.method === "POST") {
    try {
      const { username = "", password = "" } = await readForm(req);
      let role = null;
      if (username === process.env.ADMIN_USERNAME && verifyScrypt(password, process.env.ADMIN_PASSWORD_SCRYPT)) {
        role = "admin";
      } else if (Object.hasOwn(GUESTS, username) && verifyScrypt(password, GUESTS[username]?.password_scrypt)) {
        role = "guest";
      }
      if (!role) {
        return send(res, 401, loginPage("Invalid username or password."), {
          "Content-Type": "text/html; charset=utf-8",
          "X-Robots-Tag": "noindex, nofollow, noarchive"
        });
      }
      return redirect(res, "/", sessionCookie(makeSession(username, role)));
    } catch {
      return send(res, 400, loginPage("Unable to process sign-in."), { "Content-Type": "text/html; charset=utf-8" });
    }
  }
  if (url.pathname === "/logout") {
    return redirect(res, "/login", clearCookie());
  }
  if (url.pathname === "/auth/status") {
    if (!session) return send(res, 401, JSON.stringify({ authenticated: false }), { "Content-Type": "application/json" });
    return send(res, 200, JSON.stringify({ authenticated: true, role: session.role, username: session.sub }), { "Content-Type": "application/json" });
  }
  if (url.pathname === "/admin") {
    if (!session) return redirect(res, "/login");
    if (session.role !== "admin") return send(res, 403, deniedPage, { "Content-Type": "text/html; charset=utf-8" });
    const guestNames = Object.keys(GUESTS);
    const body = `<!doctype html><meta charset="utf-8"><meta name="robots" content="noindex,nofollow"><title>ANANS Preview Admin</title>
<body style="font-family:system-ui;background:#0b1511;color:#eee;padding:2rem;max-width:60rem;margin:auto">
<h1>Preview administration</h1><p>Role: admin. Current guest accounts: <strong>${guestNames.length}</strong>.</p>
<ul>${guestNames.map(name => `<li>${name.replace(/[<>&"]/g, "")}</li>`).join("") || "<li>None provisioned</li>"}</ul>
<p>Guest provisioning is configuration-backed and requires an explicit account update; no self-registration is enabled.</p>
<p><a href="/" style="color:#f1c65e">Preview</a> · <a href="/logout" style="color:#f1c65e">Sign out</a></p></body>`;
    return send(res, 200, body, { "Content-Type": "text/html; charset=utf-8" });
  }

  if (!session) return redirect(res, "/login");
  return serveStatic(req, res);
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`ANANS restricted preview listening on ${PORT}`);
  console.log(`Guest accounts configured: ${Object.keys(GUESTS).length}`);
});
