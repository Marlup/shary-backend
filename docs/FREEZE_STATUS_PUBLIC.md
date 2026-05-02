# Shary Backend Freeze Status (Public)

Last updated: 2026-05-02
Audience: Product, QA, rollout stakeholders

## Current Freeze State

- Freeze scope: backend contract and security hardening for decision, upload/fetch, identity, and scheduler flows.
- Status: implemented in runtime and verified by local backend test gate.
- Canonical decision endpoint: `/request_decision`
- Compatibility decision endpoint: `/payload_decision` (still active, with deprecation headers)

## Supported Endpoint Surface

- `GET /ping`
- `POST /login_refresh_token`
- `GET /get_pubkey`
- `POST /upload_payload`
- `POST /upload_request`
- `GET /fetch_payload`
- `GET /fetch_request`
- `POST /request_decision` (canonical)
- `POST /payload_decision` (compatibility)
- `/* /v2/identity/*` (identity routes)
- `GET /clean_expired_docs` (scheduler/internal operation)

## Compatibility and Deprecation Gate

`/payload_decision` removal is deferred until all are true:
- date is on/after `2026-07-31`
- trailing 30-day compat traffic is zero in staging and production
- explicit freeze-owner signoff is recorded

## Readiness Gates

- CI gate: GitHub Actions backend test workflow must pass (`backend-ci / pytest`).
- Branch protection must require status check `backend-ci / pytest` on protected branches.
- Smoke gate: deployed contract smoke workflow must pass on staging before user testing.
- Current local baseline: `python -m pytest -q` from `firebase/functions`.

## Public Scope Note

This document intentionally stays concise and non-sensitive.
Detailed engineering docs, internal constraints, and Codex operating guidance are maintained in local/private documentation paths.
