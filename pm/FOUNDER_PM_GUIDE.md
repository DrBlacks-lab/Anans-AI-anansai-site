# Founder PM Guide

## Control boundary

This branch is a restricted-preview implementation. Local validation may change code, tests, and receipts. Merge, push, public replacement, paid spend, external communication, production billing, legal commitment, and disclosure of non-public implementation require a fresh Founder decision.

## Release gate

Run `npm run validate`. A restricted provider deployment is eligible only when both `npm run check` and `npm test` pass and an authenticated Railway actuator is in custody. Provider health does not establish independent-browser validation.

## Semantic rule

`village/registry.json` is the canonical source for building names, purposes, backend classes, states, roles, health, blockers, and receipts. The landing page and admin surface are projections; they must not carry competing semantics.
