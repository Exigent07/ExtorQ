# extorq-lab: disposable lab repository for ExtorQ

**This repository is a disposable security lab target. It is not a product and is
never deployed.** It exists so that the ExtorQ mini-SIEM can monitor a real GitHub
repository (commits, workflow changes, workflow runs, settings, branch protection and
security alerts) and so that ExtorQ's scanners have realistic material to scan.

## What is in here

| Path | Purpose |
|---|---|
| `app/` | A tiny Flask inventory API (`/healthz`, `/api/items`). |
| `tests/` | Unit tests run by CI. |
| `.github/workflows/ci.yml` | Baseline CI with least privilege: `permissions: contents: read`, actions pinned to full commit SHAs, credentials not persisted. |
| `Dockerfile` | Container build (non-root user). |
| `requirements.txt` | Intentionally **outdated** dependency pins (Flask 2.2.2, Werkzeug 2.2.2, Jinja2 3.1.2, requests 2.28.1, ...) so dependency scanners (Trivy, Dependabot) report real, known CVEs. The service is never deployed. |
| `app/diagnostics.py` | One **intentionally insecure** pattern (`subprocess` with `shell=True` on caller input) in a function that nothing calls, for static analysis (Semgrep). |
| `deploy/legacy-staging.conf` | A **fake**, secret-shaped test string (`EXTORQ_TEST_SECRET_` + 24 characters) for a custom secret-scanning rule. It is not a credential for any system and matches no real provider token format. |

## Simulations

ExtorQ's GH-001 scenario (`simulations/github/gh_001_workflow_permissions.sh` in the
ExtorQ repository) temporarily changes `ci.yml` to grant `permissions: write-all` and
adds a `pull_request_target` job that checks out the pull request head. Simulation
commits carry the marker `[extorq-sim <run_id>]`; the scenario's cleanup restores the
baseline workflow with a new commit. Do not reuse this repository for anything else.

## Local development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest -q
flask --app app.main run --port 8080
```
