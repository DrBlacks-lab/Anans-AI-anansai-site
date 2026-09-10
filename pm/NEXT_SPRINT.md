# ANANS Village — PM Next Sprint

State: PREPARED / NOT A PUBLIC-RELEASE AUTHORIZATION

## Current bottleneck

The Village now has a first canonical semantic registry and a first truthful backend-binding registry. The highest-value missing primitive is registry-driven projection plus test evidence: visible buildings must derive their human meaning/state from the canonical registry, and every claimed live/read-only route must be tested against the actual restricted-preview surface.

## Sprint order

### S1 — Registry validation
- Parse `village/registry.json` and `village/backend-bindings.json`.
- Enforce unique `building_id` and `binding_id`.
- Require every visible landing building to exist in the registry.
- Require every consequential capability to declare `authority_required`.
- Reject a `LIVE_BACKEND` or `READ_ONLY_BACKEND` state without a concrete binding.
- Reject duplicate primitive/backend ownership unless an explicit reconciliation reason exists.

Gate: `PASS / VILLAGE_REGISTRY_INVARIANTS_VALIDATED`.

### S2 — UI projection reconciliation
- Reconcile `index.html` labels/routes against the registry.
- Do not add client-side JavaScript solely to read the registry.
- Prefer build-time/static generation or server-side projection compatible with the restricted Node gateway.
- Make implementation state available in an accessible technical detail surface without cluttering the village visual.
- Admin may see deeper binding/health detail; guest sees public/restricted semantic state only.

Gate: `PASS / VILLAGE_UI_REGISTRY_PROJECTION_RECONCILED`.

### S3 — Backend route assay
Exercise only currently bound routes: `/health`, `/login`, `/logout`, `/auth/status`, `/admin` role separation, restricted static pages, and independently reachable read-only public destinations. Capture status codes and failure behavior. Do not simulate unavailable private ANANS backends.

Gate: `PASS / CURRENT_BOUND_BACKENDS_EXERCISED` or exact HOLD/BLOCKED terminal.

### S4 — Auth hostile suite
Test valid admin, valid guest, bad password, disabled guest, expired guest, stale guest/admin session versions, tampered and expired cookies, guest `/admin` denial, rate-limit activation, denied traversal/config paths, security headers and indexing restrictions.

Gate: `PASS / RESTRICTED_PREVIEW_AUTH_HOSTILE_SUITE`.

### S5 — Approved visual fidelity
- Promote the approved 1536×1024 style/resolution parent as one background visual or responsive single-image source set.
- No tiled transport.
- Preserve semantic HTML labels and `Garth Noel` attribution.
- Validate desktop/tablet/mobile with no required horizontal scrolling.
- Record image dimensions, bytes and hashes.

Gate: `PASS / APPROVED_VILLAGE_VISUAL_FIDELITY_BOUND`.

### S6 — AEL candidate assay
Hold semantic content and authority boundaries constant. Compare meaningful image-delivery/responsive/progressive-disclosure variants. Measure render integrity, bundle cost, accessibility, route correctness, state-comprehension proxies and regressions. Retain only demonstrated improvements without governance/security/evidence regression. Evaluator preference is not user evidence.

Gate: `PASS / VILLAGE_AEL_RETAIN_REJECT_RECEIPTS_EMITTED`.

### S7 — RevLane + Track X closure
RevLane attacks state classification, unsupported claims, duplicate surfaces, stale bindings, authority leakage and metaphor/backend mismatch. Track X searches for the highest-leverage remaining in-scope improvement and performs a substitution test before adding anything. Closure requires no unresolved in-scope P0/P1 defect.

### S8 — Restricted deployment receipt
Restricted Railway redeployment is in scope. Verify deployment health and route behavior. Independent outside-network validation remains a separate evidence item if unavailable from the execution environment.

## Founder interruption threshold
Return only for public promotion/material merge, new spend, new credentials/confidential access, disclosure expansion, production/irreversible external effects, customer commitment, or an unresolved strategic fork.

## Explicit non-claims
This sprint does not authorize public replacement of the current landing page, production autonomous actuation, customer communication, billing, R9 advancement, or disclosure of private ADE/AEL/GCOS machinery.