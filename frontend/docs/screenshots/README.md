# Console screenshots (real lab data)

Captured 2026-11-21 20:56 UTC from the compose console (`http://127.0.0.1:3000`, compose `api`
behind it) with `scripts/screenshots.mjs` (local headless Chrome over the DevTools protocol,
signed in as the analyst through the real login form). Every value comes from the live
ExtorQ store at that moment: genuine scenario telemetry, real detector alerts, the real Jev
triage and Gemini overview that agent E produced for these alerts. Nothing was edited.

| File | View |
|---|---|
| `01-overview.png` | Overview: coverage per asset class, service coverage, alert trend, posture, recent alerts, collection health |
| `02-investigation-gh-001.png` | GH-001 (simulation run 8dwz3wf6zji4): evidence, timeline, Jev triage, Gemini overview with verified evidence ids |
| `03-investigation-vm-002.png` | VM-002 (simulation run b7a712bc786d): inventory + auditd evidence, candidate/direct links, Jev triage |
| `04-kind-node-workloads.png` | Kubernetes node `extorq-lab-control-plane`: cluster workloads and their Pods/containers on the node |
| `05-detections.png` | Detections: alert history (last 7 days) and the rules table |

Recapture (read-only; the password is read from a file and never printed):

```bash
EXTORQ_SHOTS_PASSWORD_FILE=../var/secrets/analyst_password \
node --experimental-websocket scripts/screenshots.mjs --base http://127.0.0.1:3000 \
  --out docs/screenshots 01-overview=/ 05-detections=/detections
```

The pictures show lab asset names, simulation markers and the lab GitHub repository; they
contain no credentials. `docs/` is excluded from the console image (`.dockerignore`).
