import { readFile } from 'node:fs/promises';
import assert from 'node:assert/strict';

const registry = JSON.parse(await readFile(new URL('../village/registry.json', import.meta.url), 'utf8'));
const bindings = JSON.parse(await readFile(new URL('../village/backend-bindings.json', import.meta.url), 'utf8'));
const index = await readFile(new URL('../index.html', import.meta.url), 'utf8');

const allowedStates = new Set(registry.implementation_states);
const buildings = registry.buildings;
const bindingRows = bindings.bindings;

assert.ok(Array.isArray(buildings) && buildings.length > 0, 'registry must contain buildings');
assert.ok(Array.isArray(bindingRows) && bindingRows.length > 0, 'backend binding registry must contain bindings');

const buildingIds = buildings.map(x => x.building_id);
assert.equal(new Set(buildingIds).size, buildingIds.length, 'building_id values must be unique');

const bindingIds = bindingRows.map(x => x.binding_id);
assert.equal(new Set(bindingIds).size, bindingIds.length, 'binding_id values must be unique');

for (const building of buildings) {
  assert.ok(building.building_id, 'every building needs building_id');
  assert.ok(building.public_name, `${building.building_id}: public_name required`);
  assert.ok(building.public_purpose, `${building.building_id}: public_purpose required`);
  assert.ok(allowedStates.has(building.implementation_state), `${building.building_id}: unknown implementation_state`);
  assert.equal(typeof building.authority_required, 'boolean', `${building.building_id}: authority_required must be boolean`);
  assert.equal(typeof building.receipt_required, 'boolean', `${building.building_id}: receipt_required must be boolean`);
  assert.ok(Array.isArray(building.primitive_bindings), `${building.building_id}: primitive_bindings must be array`);
  assert.ok(Array.isArray(building.routes), `${building.building_id}: routes must be array`);
  assert.ok(Array.isArray(building.non_claims), `${building.building_id}: non_claims must be array`);
}

const registryIds = new Set(buildingIds);
for (const binding of bindingRows) {
  assert.ok(registryIds.has(binding.building_id), `${binding.binding_id}: building_id missing from registry`);
  assert.ok(allowedStates.has(binding.implementation_state), `${binding.binding_id}: unknown implementation_state`);
  assert.ok(Array.isArray(binding.routes), `${binding.binding_id}: routes must be array`);
  assert.ok(Array.isArray(binding.terminal_outcomes), `${binding.binding_id}: terminal_outcomes must be array`);
  assert.ok(Array.isArray(binding.failure_conditions), `${binding.binding_id}: failure_conditions must be array`);
  if (['LIVE_BACKEND', 'READ_ONLY_BACKEND'].includes(binding.implementation_state)) {
    assert.ok(binding.implementation_surface, `${binding.binding_id}: operational binding needs implementation_surface`);
    assert.ok(binding.routes.length > 0, `${binding.binding_id}: operational binding needs at least one route`);
  }
}

for (const building of buildings.filter(x => ['LIVE_BACKEND', 'READ_ONLY_BACKEND'].includes(x.implementation_state))) {
  assert.ok(bindingRows.some(b => b.building_id === building.building_id && b.implementation_state === building.implementation_state), `${building.building_id}: operational registry state requires matching backend binding`);
}

const visibleNames = [...index.matchAll(/<a class="place [^"]+"[^>]*><strong>([^<]+)<\/strong>/g)].map(m => m[1].replace(/&amp;/g, '&').trim());
assert.ok(visibleNames.length >= 8, 'expected visible village building labels in landing page');
const registryNames = new Set(buildings.map(x => x.public_name));
for (const name of visibleNames) assert.ok(registryNames.has(name), `visible landing building missing from registry: ${name}`);

// Authority belongs to consequential action surfaces, not to mere discussion of an
// authority concept. A read-only Court page may explain authority without requiring
// permission to read it. These institutions either execute/mediate consequential
// access today or are specified to do so when implemented.
const authorityControlledBuildings = new Set(['gate', 'workshop', 'laboratory', 'market', 'farm_resources', 'guest_house']);
for (const building of buildings) {
  if (authorityControlledBuildings.has(building.building_id)) {
    assert.equal(building.authority_required, true, `${building.building_id}: consequential action surface must require authority`);
  }
}

assert.ok(!index.includes('village-pair-'), 'tiled village image transport must not reappear in landing page');
assert.ok(index.includes('Garth Noel'), 'approved quote attribution must remain Garth Noel');

console.log(JSON.stringify({
  terminal: 'PASS / VILLAGE_REGISTRY_INVARIANTS_VALIDATED',
  building_count: buildings.length,
  backend_binding_count: bindingRows.length,
  visible_landing_building_count: visibleNames.length
}, null, 2));
