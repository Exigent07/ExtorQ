# Console screenshots (real lab data)

Captured 2026-11-22 06:31-06:34 UTC from a production build of the console (`pnpm build &&
pnpm start` on `http://127.0.0.1:3100`) over the compose analyst API (`http://127.0.0.1:8000`),
with `scripts/screenshots.mjs` (local headless Chrome over the DevTools protocol, signed in as the
analyst through the real login form). Every value comes from the live ExtorQ store at that
moment: genuine scenario telemetry, real detector alerts, real scan findings. Nothing was edited.

| File | View |
|---|---|
| `00-login.png` | Sign-in page, 1440x900 (signed out) |
| `01-overview-1440x900.png` | Overview, first screen at 1440x900: KPI row, alert activity, asset coverage |
| `01-overview.png` | Overview, full page: plus recent important alerts, collection health, service coverage, findings by severity |
| `01-command-palette.png` | Overview with the Cmd/Ctrl-K palette open (pages, recent alerts, assets) |
| `01-overview-phone.png` | Overview at 390 px (sidebar folded into a sheet) |
| `02-investigation-gh-001.png` | GH-001 investigation in the new shell (page layout not rebuilt yet) |
| `03-investigation-vm-002.png` | VM-002 investigation in the new shell (page layout not rebuilt yet) |
| `04-kind-node-workloads.png` | Kubernetes node `extorq-lab-control-plane`, workloads tab (the yellow "Stale" Pod badges are the instance-refresh data issue tracked as D1-IC-8, fixed in parallel) |
| `05-detections.png` | Detections: alert history and rules in the new shell (page layout not rebuilt yet) |

Login and Overview are the reference implementation of `frontend/DESIGN.md`; the other routes
already use the new shell, cards, badges and UntrustedText, and are rebuilt by later stages.

Recapture (read-only; the password is read from a file and never printed). Pace the runs: the
API's ClickHouse read quota is shared.

```bash
export EXTORQ_SHOTS_PASSWORD_FILE=../var/secrets/analyst_password
node --experimental-websocket scripts/screenshots.mjs --base http://127.0.0.1:3100 \
  --out docs/screenshots --anon --first-screen 00-login=/login
node --experimental-websocket scripts/screenshots.mjs --base http://127.0.0.1:3100 \
  --out docs/screenshots --first-screen 01-overview-1440x900=/
node --experimental-websocket scripts/screenshots.mjs --base http://127.0.0.1:3100 \
  --out docs/screenshots 01-overview=/ 05-detections=/detections
node --experimental-websocket scripts/screenshots.mjs --base http://127.0.0.1:3100 \
  --out docs/screenshots --first-screen --press Meta+k 01-command-palette=/
EXTORQ_SHOTS_WIDTH=390 EXTORQ_SHOTS_HEIGHT=844 node --experimental-websocket \
  scripts/screenshots.mjs --base http://127.0.0.1:3100 --out docs/screenshots 01-overview-phone=/
```

The pictures show lab asset names, simulation markers and the lab GitHub repository; they
contain no credentials. `docs/` is excluded from the console image (`.dockerignore`).
