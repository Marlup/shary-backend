# Shary Backend (Firebase Functions)

Backend service for Shary contract, identity, upload/fetch, and request-decision flows.

## Current Status

- Freeze implementation is active in runtime.
- Canonical decision endpoint: `/request_decision`.
- Compatibility endpoint: `/payload_decision` (temporary, with deprecation headers).
- Public freeze/readiness summary: [`docs/FREEZE_STATUS_PUBLIC.md`](/C:/main_work/shary-project/shary-backend/docs/FREEZE_STATUS_PUBLIC.md).

## Repo Layout

- `firebase/functions`: Cloud Functions Python runtime and tests.
- `firebase/firebase.json`: function target exports and emulator config.
- `docs`: tracked public docs.
- `firebase/docs` and `firebase/docs-local`: local/private engineering docs (not public-tracked).

## Local Development

From `firebase/functions`:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install pytest
python -m pytest -q
```

Current backend test baseline is expected to pass.

## CI and Smoke Workflows

- CI test gate: `.github/workflows/backend-ci.yml`
- Deployed smoke/contract checks: `.github/workflows/backend-smoke.yml`

Smoke workflow inputs and secrets:

- Input: `base_url` (staging Cloud Functions base URL)
- Secrets:
  - `SMOKE_AUTH_BEARER`
  - `SMOKE_RECIPIENT_HASH`
  - `SMOKE_REQUEST_HASH`

## Branch Protection Requirement

Configure protected branches to require status check:

- `backend-ci / pytest`

Without this, CI runs but is not an enforced merge gate.

## Compatibility Removal Gate (`/payload_decision`)

Remove compatibility endpoint only when all are true:

- Date is on/after `2026-07-31`.
- Trailing 30-day compat traffic is zero in staging and production.
- Explicit freeze-owner signoff is recorded.

## User-Testing Readiness Checklist

1. `python -m pytest -q` passes locally.
2. `backend-ci` passes in GitHub Actions.
3. Branch protection requires `backend-ci / pytest`.
4. `backend-smoke` passes against staging.
5. Smoke run URL and run number are attached to rollout readiness notes.
