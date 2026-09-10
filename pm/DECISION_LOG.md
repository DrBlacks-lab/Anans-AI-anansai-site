# ANANS Village — PM Decision Log

## 2026-09-10 — PM control activated

Decision: manage the restricted ANANS Village build under `pm/FOUNDER_PM_GUIDE.md` and `pm/PROJECT_CHARTER.json`.

Reason: the project has moved from visual concept into semantic/backend integration. Founder attention should be reserved for authority, release, spend, disclosure and strategic forks; ordinary preview engineering remains PM-controlled.

Authority delta: 0.

## 2026-09-10 — Canonical semantic registry introduced

Decision: `village/registry.json` becomes the first canonical candidate for the human-readable Village ontology. `village/backend-bindings.json` records only backend/static/manual surfaces actually evidenced in this website repository or explicitly identified external read-only release surface.

Non-claim: this does not bind private ANANS backend machinery that is not in custody here.

## 2026-09-10 — RevLane correction to authority invariant

Initial invariant incorrectly treated the presence of an authority-related semantic primitive as evidence that reading the building itself required authority. Railway correctly rejected the first registry test with:

`AssertionError: court: consequential primitive must require authority`

Corrected model: **semantic discussion of authority != consequential execution authority**. A read-only Court documentation page can explain authority without requiring permission to read it. Authority gates apply to the action surface, not merely to vocabulary used by the surface.

The corrected invariant explicitly binds authority requirements to institutions that execute, mediate or are specified to mediate consequential access/actions.

Result after correction:

`PASS / VILLAGE_REGISTRY_INVARIANTS_VALIDATED`

Observed counts:
- buildings: 12
- backend bindings: 12
- visible landing buildings: 10

Railway deployment carrying the corrected test: `2f36b699-47bc-419c-9586-8ad477416a79` — SUCCESS.

Authority delta: 0.

## Standing decision

The next build target is registry-driven projection and live/read-only route assay. Do not spend the next sprint on cosmetic village variants unless a visual defect blocks usability or the approved 1536×1024 fidelity contract.