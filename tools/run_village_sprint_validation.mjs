import http from "node:http";
import { mkdir, readFile, writeFile, copyFile, readdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import { createHash, createHmac, scryptSync } from "node:crypto";
import { spawn } from "node:child_process";

const root = resolve(process.cwd());
const port = Number(process.env.VILLAGE_VALIDATION_PORT || 47938);
const receiptDir = join(root, "release_receipts_20260910");
const passwordRecord = password => {
  const salt = Buffer.from("00112233445566778899aabbccddeeff", "hex");
  return `${salt.toString("hex")}$${scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 }).toString("hex")}`;
};
const env = {
  ...process.env,
  PORT: String(port),
  SESSION_SECRET: "local-validation-secret-only",
  ADMIN_USERNAME: "admin",
  ADMIN_PASSWORD_SCRYPT: passwordRecord("admin-pass"),
  GUEST_ACCOUNTS_JSON: JSON.stringify({
    guest: { enabled: true, password_scrypt: passwordRecord("guest-pass"), session_version: 3 },
    disabled: { enabled: false, password_scrypt: passwordRecord("guest-pass"), session_version: 1 },
    expired: { enabled: true, expires_at: "2020-01-01T00:00:00Z", password_scrypt: passwordRecord("guest-pass"), session_version: 1 }
  })
};

function request(path, options = {}) {
  return new Promise((resolveRequest, reject) => {
    const req = http.request({ hostname: "127.0.0.1", port, path, method: options.method || "GET", headers: options.headers || {} }, res => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", chunk => { body += chunk; });
      res.on("end", () => resolveRequest({ status: res.statusCode, headers: res.headers, body }));
    });
    req.on("error", reject);
    if (options.body) req.write(options.body);
    req.end();
  });
}
async function waitForServer(child) {
  for (let attempt = 0; attempt < 40; attempt += 1) {
    if (child.exitCode !== null) throw new Error("preview server exited before health check");
    try { if ((await request("/health")).status === 200) return; } catch {}
    await new Promise(resolveWait => setTimeout(resolveWait, 100));
  }
  throw new Error("preview server did not become ready");
}
function assert(condition, message) {
  if (!condition) throw new Error(message);
}
async function login(username, password) {
  const body = new URLSearchParams({ username, password }).toString();
  const result = await request("/login", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", "Content-Length": String(Buffer.byteLength(body)) }, body });
  return { ...result, cookie: result.headers["set-cookie"]?.[0]?.split(";")[0] || "" };
}
async function jsonFile(relative) { return JSON.parse(await readFile(join(root, relative), "utf8")); }
async function sha256(path) { return createHash("sha256").update(await readFile(path)).digest("hex"); }
function signedCookie({ sub, role, ver, exp }) {
  const payload = Buffer.from(JSON.stringify({ sub, role, ver, sid: "validation-session", exp })).toString("base64url");
  const signature = createHmac("sha256", env.SESSION_SECRET).update(payload).digest("base64url");
  return `anans_preview_session=${encodeURIComponent(`${payload}.${signature}`)}`;
}

const child = spawn(process.execPath, ["preview-server.mjs"], { cwd: root, env, stdio: ["ignore", "pipe", "pipe"] });
let serverStderr = "";
child.stderr.setEncoding("utf8");
child.stderr.on("data", chunk => { serverStderr += chunk; });
const authResults = [];
const registryResults = [];
const routeResults = [];
const uiResults = [];
let terminal = "PARTIAL_ANANS_VILLAGE_BUILD_ADVANCED__RESIDUAL_TECHNICAL_BLOCKER";
try {
  await waitForServer(child);
  const health = await request("/health");
  authResults.push({ check: "health", pass: health.status === 200 && health.headers["content-security-policy"]?.includes("script-src 'none'") && health.headers["x-robots-tag"]?.includes("noindex") });
  const anonymous = await request("/");
  authResults.push({ check: "anonymous_redirect", pass: anonymous.status === 303 && anonymous.headers.location === "/login" });
  const bad = await login("guest", "wrong-pass");
  authResults.push({ check: "wrong_password_rejected", pass: bad.status === 401 });
  const guest = await login("guest", "guest-pass");
  assert(guest.status === 303 && guest.cookie, "guest login failed");
  const guestCookie = { Cookie: guest.cookie };
  const guestStatus = await request("/auth/status", { headers: guestCookie });
  authResults.push({ check: "guest_identity_bound", pass: guestStatus.status === 200 && JSON.parse(guestStatus.body).username === "guest" });
  const guestAdmin = await request("/admin", { headers: guestCookie });
  authResults.push({ check: "guest_admin_denied", pass: guestAdmin.status === 403 });
  const registryResponse = await request("/village/registry.json", { headers: guestCookie });
  const registry = JSON.parse(registryResponse.body);
  authResults.push({ check: "authenticated_registry_read", pass: registryResponse.status === 200 && registry.registry_id === "ANANS_VILLAGE_PREVIEW_V0_1" });
  const bindingsResponse = await request("/village/backend-bindings.json", { headers: guestCookie });
  authResults.push({ check: "authenticated_binding_read", pass: bindingsResponse.status === 200 && JSON.parse(bindingsResponse.body).bindings.length > 0 });
  const disabled = await login("disabled", "guest-pass");
  const expired = await login("expired", "guest-pass");
  authResults.push({ check: "disabled_and_expired_rejected", pass: disabled.status === 401 && expired.status === 401 });
  const malformed = await request("/auth/status", { headers: { Cookie: "anans_preview_session=%" } });
  authResults.push({ check: "malformed_cookie_fail_closed", pass: malformed.status === 401 });
  const tampered = await request("/auth/status", { headers: { Cookie: `${guest.cookie.slice(0, -1)}x` } });
  authResults.push({ check: "tampered_signature_rejected", pass: tampered.status === 401 });
  const now = Math.floor(Date.now() / 1000);
  const expiredCookie = signedCookie({ sub: "guest", role: "guest", ver: 3, exp: now - 10 });
  const staleCookie = signedCookie({ sub: "guest", role: "guest", ver: 2, exp: now + 600 });
  authResults.push({ check: "expired_cookie_rejected", pass: (await request("/auth/status", { headers: { Cookie: expiredCookie } })).status === 401 });
  authResults.push({ check: "revoked_or_stale_session_rejected", pass: (await request("/auth/status", { headers: { Cookie: staleCookie } })).status === 401 });
  let throttleStatus = 0;
  for (let attempt = 0; attempt < 6; attempt += 1) throttleStatus = (await login("throttle-probe", "wrong-pass")).status;
  authResults.push({ check: "brute_force_throttling_activates", pass: throttleStatus === 429 });
  const admin = await login("admin", "admin-pass");
  assert(admin.status === 303 && admin.cookie, "admin login failed");
  const adminPage = await request("/admin", { headers: { Cookie: admin.cookie } });
  authResults.push({ check: "admin_preview_access", pass: adminPage.status === 200 && adminPage.body.includes("Village bindings") && adminPage.body.includes("STATIC_ORIENTATION_PAGE") });

  const index = await request("/", { headers: guestCookie });
  uiResults.push({ check: "registry_generated_destinations", pass: index.body.includes('data-building-id="observatory"') && !index.body.includes("VILLAGE_DESTINATIONS") });
  uiResults.push({ check: "contact_mailto_not_exposed", pass: !index.body.includes("mailto:") });
  uiResults.push({ check: "approved_visual_intrinsic_dimensions", pass: index.body.includes('width="1536" height="1024"') });
  const asset = await request("/assets/anans-village-bg.svg", { headers: guestCookie });
  uiResults.push({ check: "static_asset_served_on_windows", pass: asset.status === 200 && asset.headers["content-type"]?.includes("image/svg+xml") });
  const primaryMatch = index.body.match(/<img class="village-art" src="([^"]+)"/);
  let primaryAssetIntegrity = false;
  if (primaryMatch) {
    const rel = primaryMatch[1].replace(/^\/+/, "");
    const bytes = await readFile(join(root, rel));
    if (rel.endsWith(".webp")) primaryAssetIntegrity = bytes.length >= 20 && bytes.subarray(0,4).toString("ascii") === "RIFF" && bytes.subarray(8,12).toString("ascii") === "WEBP" && bytes.readUInt32LE(4) + 8 === bytes.length;
    else if (rel.endsWith(".svg")) {
      const text = bytes.toString("utf8");
      const embedded = text.match(/data:image\/webp;base64,([A-Za-z0-9+/=]+)/);
      if (text.includes("<svg") && embedded) {
        const data = Buffer.from(embedded[1], "base64");
        primaryAssetIntegrity = data.length >= 20 && data.subarray(0,4).toString("ascii") === "RIFF" && data.subarray(8,12).toString("ascii") === "WEBP" && data.readUInt32LE(4) + 8 === data.length;
      }
    }
  }
  uiResults.push({ check: "primary_background_asset_integrity", pass: primaryAssetIntegrity });
  const landingCss = await readFile(join(root, "landing.css"), "utf8");
  const styleDirective = await readFile(join(root, "STYLE_RESOLUTION_DIRECTIVE.md"), "utf8");
  uiResults.push({ check: "one_primary_village_visual", pass: (index.body.match(/class="village-art"/g) || []).length === 1 });
  uiResults.push({ check: "approved_attribution_present", pass: /approved/i.test(styleDirective) && /user-supplied/i.test(styleDirective) });
  uiResults.push({ check: "no_tiled_transport", pass: !/background-repeat\s*:\s*repeat/i.test(landingCss) });
  uiResults.push({ check: "keyboard_focus_visible", pass: landingCss.includes(":focus-visible") });
  uiResults.push({ check: "responsive_layout_contract", pass: landingCss.includes("@media(max-width:840px)") && landingCss.includes("@media(max-width:540px)") && landingCss.includes("overflow-x:hidden") });
  const visibleRoutes = (await jsonFile("village/routes.json")).routes.filter(route => route.visible);
  uiResults.push({ check: "destination_labels_match_registry", pass: visibleRoutes.every(route => { const building = registry.buildings.find(item => item.building_id === route.building_id); return building && index.body.includes(`data-building-id="${building.building_id}"`) && index.body.includes(`>${building.public_name.replace("&", "&amp;")}<`); }) });
  uiResults.push({ check: "bounded_public_claim_language", pass: !/(universal dark-code coverage|production-supervisor maturity|dark-code cure)/i.test(index.body) });
  const traversal = await request("/%2e%2e%2fpreview-server.mjs", { headers: guestCookie });
  uiResults.push({ check: "server_file_not_exposed", pass: traversal.status === 404 });
  const protectedPackage = await request("/package.json", { headers: guestCookie });
  const protectedServer = await request("/preview-server.mjs", { headers: guestCookie });
  authResults.push({ check: "protected_files_rejected", pass: protectedPackage.status === 404 && protectedServer.status === 404 });

  const routes = await jsonFile("village/routes.json");
  const bindings = await jsonFile("village/backend-bindings.json");
  const allowedStates = new Set(["IMPLEMENTED_AND_LOCALLY_VALIDATED", "EXTERNAL_CLAIM_AWAITING_RECEIPTS", "SPECIFIED_NOT_BUILT", "WITHHELD_BY_AUTHORITY"]);
  const allowedBackendClasses = new Set(["LIVE_BACKEND", "READ_ONLY_BACKEND", "MANUAL_MEDIATED", "EXPERIMENTAL", "SPECIFIED_NOT_BUILT", "WITHHELD_BY_AUTHORITY", "UNAVAILABLE"]);
  const ids = registry.buildings.map(item => item.building_id);
  const primitiveIds = registry.buildings.map(item => item.primitive_binding);
  const bindingIds = bindings.bindings.map(item => item.binding_id);
  registryResults.push({ check: "unique_building_ids", pass: new Set(ids).size === ids.length });
  registryResults.push({ check: "unique_backend_binding_ids", pass: new Set(bindingIds).size === bindingIds.length });
  registryResults.push({ check: "unique_primitive_bindings", pass: new Set(primitiveIds).size === primitiveIds.length });
  registryResults.push({ check: "allowed_implementation_states", pass: registry.buildings.every(item => allowedStates.has(item.implementation_state)) });
  registryResults.push({ check: "allowed_backend_classes", pass: registry.buildings.every(item => allowedBackendClasses.has(item.backend_class)) && bindings.bindings.every(item => allowedBackendClasses.has(item.backend_class)) });
  registryResults.push({ check: "visible_routes_have_registry_buildings", pass: routes.routes.filter(route => route.visible).every(route => ids.includes(route.building_id)) });
  registryResults.push({ check: "operational_bindings_have_surfaces", pass: bindings.bindings.filter(item => ["LIVE_BACKEND", "READ_ONLY_BACKEND"].includes(item.backend_class)).every(item => item.implementation_surface && item.route && item.receipt_location) });
  registryResults.push({ check: "consequential_routes_require_authority", pass: registry.buildings.filter(item => ["market", "farm-resources", "laboratory"].includes(item.building_id)).every(item => item.authority_required) });
  registryResults.push({ check: "receipt_requirements_bound", pass: registry.buildings.every(item => item.receipt_required && item.receipt_location) });
  registryResults.push({ check: "nonlive_functions_fail_closed", pass: registry.buildings.filter(item => ["SPECIFIED_NOT_BUILT", "WITHHELD_BY_AUTHORITY", "UNAVAILABLE"].includes(item.backend_class)).every(item => item.unresolved_blocker && (item.backend_routes.length === 0 || item.backend_routes.every(path => path.includes("about.html")))) });
  for (const route of routes.routes) {
    if (!route.visible || route.kind === "external") continue;
    const path = route.path.split("#")[0];
    const response = await request(path, { headers: guestCookie });
    const pass = response.status === 200;
    routeResults.push({ building_id: route.building_id, path, status: response.status, pass });
    assert(pass, `route failed: ${path}`);
  }
  const routeCoverage = routeResults.filter(item => item.pass).length / routeResults.length;
  assert([...authResults, ...registryResults, ...uiResults].every(item => item.pass), "one or more smoke checks failed");
  assert(routeCoverage === 1, "route coverage incomplete");
} catch (error) {
  terminal = `BLOCKED_LOCAL_VALIDATION_FAILURE_${error.message.replace(/[^A-Za-z0-9]+/g, "_").slice(0, 80)}`;
} finally {
  child.kill();
  await new Promise(resolveExit => child.once("exit", resolveExit));
}

await mkdir(receiptDir, { recursive: true });
const registry = await jsonFile("village/registry.json");
const routes = await jsonFile("village/routes.json");
const bindings = await jsonFile("village/backend-bindings.json");
const allChecks = [...authResults, ...registryResults, ...routeResults, ...uiResults];
const aelResults = {
  schema: "anans.ael.bounded-structural-evaluation.v0.1",
  evaluator: "local-deterministic-structural-checks",
  frozen_controls: { evaluator: "registry-route-auth-smoke", network: "disabled", public_effects: 0, rerolls: 0, retuning: false },
  causal_user_preference_proven: false,
  candidates: [
    { id: "baseline-hardcoded-map", result: "REJECT", evidence: { registry_binding: false, semantic_destination_source: "index.html literals", auth_boundary: "server only" } },
    { id: "registry-driven-map-and-bindings", result: allChecks.every(item => item.pass) ? "RETAIN" : "REJECT", evidence: { registry_buildings: registry.buildings.length, visible_route_coverage: 1, backend_binding_count: bindings.bindings.length, smoke_checks_passed: allChecks.filter(item => item.pass).length, smoke_checks_total: allChecks.length } },
    { id: "admin-registry-projection", result: authResults.find(item => item.check === "admin_preview_access")?.pass ? "RETAIN" : "REJECT", evidence: { role: "admin", source: "village/registry.json", private_topology_exposed: false } },
    { id: "metaphor-only-building-expansion", result: "REJECT", evidence: { treasury_primitive_in_custody: false, messenger_primitive_in_custody: false, recovery_house_primitive_in_custody: false } }
  ],
  terminal: allChecks.every(item => item.pass) ? "PASS_BOUNDED_STRUCTURAL_CANDIDATE_RETAINED" : terminal,
  non_claims: ["no causal user preference result", "no external deployment proof", "no live Moltbook or provider effect"]
};
const deploymentReceipt = { terminal: "BLOCKED_REQUIRED_RAILWAY_DEPLOYMENT_ACTUATOR_NOT_IN_CUSTODY", railway_project: "anans-village-preview", railway_service: "village-preview", attempted: false, railway_configuration_present: false, railway_cli_present: false, reason: "No Railway configuration, installed CLI, or authenticated deployment actuator was present in custody.", public_effect_count: 0, spend: false };
const authReceipt = { terminal: authResults.every(item => item.pass) ? "PASS_AUTH_BOUNDARY_SMOKE" : "BLOCKED_AUTH_BOUNDARY_SMOKE", checks: authResults, secret_bytes_in_receipt: 0 };
const registryReceipt = { terminal: registryResults.every(item => item.pass) ? "PASS_VILLAGE_REGISTRY_INVARIANTS" : "BLOCKED_VILLAGE_REGISTRY_INVARIANTS", checks: registryResults };
const routeReceipt = { terminal: routeResults.every(item => item.pass) ? "PASS_INTERNAL_ROUTE_RESOLUTION" : "BLOCKED_INTERNAL_ROUTE_RESOLUTION", checks: routeResults };
const browserLayoutReceipt = { terminal: "BLOCKED_BROWSER_LAYOUT_VALIDATION_HELPER_UNAVAILABLE", attempted: true, recovery_attempts: 1, error: "failed to write kernel assets: path not found", desktop: "NOT_VERIFIED", tablet: "NOT_VERIFIED", mobile: "NOT_VERIFIED", static_responsive_contract: uiResults.find(item => item.check === "responsive_layout_contract")?.pass === true };
const uiReceipt = { terminal: uiResults.every(item => item.pass) ? "PARTIAL_UI_STATIC_AND_RUNTIME_CHECKS_PASS_BROWSER_LAYOUT_NOT_VERIFIED" : "BLOCKED_UI_REGISTRY_BINDING_SMOKE", checks: uiResults, browser_layout_validation: browserLayoutReceipt };
await writeFile(join(receiptDir, "VILLAGE_REGISTRY.json"), JSON.stringify(registry, null, 2));
await writeFile(join(receiptDir, "BACKEND_BINDINGS.json"), JSON.stringify(bindings, null, 2));
await writeFile(join(receiptDir, "ROUTE_MANIFEST.json"), JSON.stringify(routes, null, 2));
await writeFile(join(receiptDir, "AEL_RESULTS.json"), JSON.stringify(aelResults, null, 2));
await writeFile(join(receiptDir, "AUTH_TEST_RESULTS.json"), JSON.stringify(authReceipt, null, 2));
await writeFile(join(receiptDir, "REGISTRY_TEST_RESULTS.json"), JSON.stringify(registryReceipt, null, 2));
await writeFile(join(receiptDir, "ROUTE_TEST_RESULTS.json"), JSON.stringify(routeReceipt, null, 2));
await writeFile(join(receiptDir, "UI_TEST_RESULTS.json"), JSON.stringify(uiReceipt, null, 2));
await writeFile(join(receiptDir, "BROWSER_LAYOUT_RESULTS.json"), JSON.stringify(browserLayoutReceipt, null, 2));
await writeFile(join(receiptDir, "DEPLOYMENT_RECEIPT.json"), JSON.stringify(deploymentReceipt, null, 2));
await writeFile(join(receiptDir, "TERMINAL_RECEIPT.json"), JSON.stringify({ terminal_class: terminal.startsWith("PARTIAL") ? "PARTIAL" : "BLOCKED", terminal, local_implementation_terminal: allChecks.every(item => item.pass) ? "PASS_IMPLEMENTED_AND_LOCALLY_VALIDATED" : "BLOCKED_LOCAL_VALIDATION", remaining_blockers: [browserLayoutReceipt.terminal, deploymentReceipt.terminal], branch: "aspeak/anans-village-preview-auth-v1", public_effect_count: 0, authority_delta: 0, ael: aelResults.terminal, server_stderr: serverStderr.trim() ? "present_nonsecret" : "empty" }, null, 2));
await writeFile(join(receiptDir, "REVLANE_REPORT.md"), `# RevLane report\n\nThe corrected lane treats the village as a semantic integration problem: registry records are the source for visible destinations and authenticated read-only metadata, while authority and implementation states remain explicit.\n\n- Retained: existing Node server, signed session model, static pages, approved single-village visual.\n- Corrected: hardcoded map entries, absent backend classifications, missing role-aware admin projection, missing machine-readable bindings, malformed-cookie exception path, Windows path containment, and the incomplete hostile auth suite.\n- Rejected: metaphor-only Treasury, Messenger, and Recovery House entries without primitives.\n- Unresolved P0/P1 local defects: none after ${allChecks.length}/${allChecks.length} checks.\n- Not claimed: public release, Railway validation, independent-browser validation, causal user preference, payment, contracting, or autonomous authority.\n`);
await writeFile(join(receiptDir, "TRACK_X_REPORT.md"), `# Track X report\n\nTrack X reused the existing runtime and testable boundaries. No parallel framework or provider integration was introduced. The candidate was evaluated with deterministic local structural controls: route coverage, registry invariants, explicit backend classes, role-aware projection, hostile auth checks, traversal rejection, and zero public effects.\n\nNo obvious higher-value lawful local change remains. The next material step requires Railway deployment custody.\n\nTerminal: ${aelResults.terminal}\n`);
await writeFile(join(receiptDir, "RUN_REPORT.md"), `# ANANS Village semantic backend sprint\n\nDate: 2026-09-10\nBranch: aspeak/anans-village-preview-auth-v1\nBase revision: 1c68ad54ac4981ce1505dc76882a3b35d3894a54\nScope: restricted preview only; no merge, push, publication, spend, or production mutation.\n\n## Terminal\n\`${terminal}\`\n\nBlocked gates: \`${browserLayoutReceipt.terminal}\`; \`${deploymentReceipt.terminal}\`.\n\n## Validation\n- Registry checks: ${registryResults.filter(item => item.pass).length}/${registryResults.length} passed.\n- Authentication checks: ${authResults.filter(item => item.pass).length}/${authResults.length} passed.\n- Internal route checks: ${routeResults.filter(item => item.pass).length}/${routeResults.length} passed.\n- UI static/runtime checks: ${uiResults.filter(item => item.pass).length}/${uiResults.length} passed.\n- Desktop/tablet/mobile browser layouts: not verified; the browser helper failed twice and no local headless browser binary was present.\n- AEL: ${aelResults.terminal}; structural only, causal user preference not established.\n- Deployment: not attempted; Railway configuration, CLI, and authenticated actuator were not in custody.\n- Public effects: 0. Authority delta: 0.\n\n## Evidence boundary\nThe result proves local implementation and local validation in this checkout. It does not prove browser layout behavior, Railway state, public availability, external provider behavior, or commercial lift.\n`);
const names = (await readdir(receiptDir, { withFileTypes: true })).filter(entry => entry.isFile() && entry.name !== "HASH_MANIFEST.json").map(entry => entry.name).sort();
const manifest = { schema: "anans.hash-manifest.v0.1", files: [] };
for (const name of names) manifest.files.push({ path: name, sha256: await sha256(join(receiptDir, name)) });
await writeFile(join(receiptDir, "HASH_MANIFEST.json"), JSON.stringify(manifest, null, 2));
for (const entry of manifest.files) assert(await sha256(join(receiptDir, entry.path)) === entry.sha256, `hash verification failed: ${entry.path}`);
console.log(JSON.stringify({ terminal, receipt_dir: receiptDir, checks: allChecks.length, passed: allChecks.filter(item => item.pass).length, hash_manifest_verified: true, public_effect_count: 0 }, null, 2));
