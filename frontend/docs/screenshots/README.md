# Console screenshots (real data)

> **Outdated set, retake pending.** These captures predate contract schema 2.0 and the
> 2026-11-22 product decisions. They still show UI that no longer exists: the LAB environment
> pill and the "Security console · Lab" sidebar line, Simulation badges and the Simulation facet,
> the "simulation-tagged" KPI line, the Gemini overview card and its "Generate overview" button,
> and the asset "Environment" fact. Retake the set with `scripts/screenshots.mjs` (command in
> `frontend/AGENTS.md`) once the database has been cleared and every asset re-verified with
> the detection-test matrix, so the images show the current console over real test activity.

Captured 2026-11-22 14:16-14:36 UTC from the compose console (`http://127.0.0.1:3000`, image
`extorq/frontend:0.1.0` rebuilt from this tree) over the compose analyst API, with
`scripts/screenshots.mjs` (local headless Chrome over the DevTools protocol, signed in as the
analyst through the real login form). Every value comes from the live ExtorQ store at that moment:
genuine scenario telemetry, real detector alerts, real scan findings, stored AI assessments.
Nothing was edited. Each capture also ran the layout audit (`--audit`: no sideways scroll, no
text under 12 px) and the console check (no errors, exceptions or CSP violations).

Each view has a first screen at 1440x900 (`*-1440x900.png`) and a full-page capture at 1440 px
width (`*.png`); `19-*` are the 1024 px checks (first screen `*-1024x768.png`, full page
`*-1024.png`), `20-*` the phone checks (`*-390x844.png`), `21-*` states (not found, the
evidence sheet). 149 files.

| View | First screen | Full page |
|---|---|---|
| Sign-in page (signed out) | `00-login-1440x900.png` | - |
| Overview: KPI row, alert activity by severity, asset coverage, recent important alerts, collection health, service coverage, findings by severity | `01-overview-1440x900.png` | `01-overview.png` |
| Overview with the Cmd/Ctrl-K palette open (pages, recent alerts, assets) | `01-command-palette-1440x900.png` | - |
| Assets: asset cards by class (collectors, last event, open alerts, findings and service coverage bars), owner accounts, stale notice | `02-assets-1440x900.png` | `02-assets.png` |
| macOS host `macos:workstation-01`, overview tab (KPIs, telemetry sources, events by source, inventory, recent alerts, attributes, service coverage) | `03-macos-host-overview-1440x900.png` | `03-macos-host-overview.png` |
| macOS host `macos:workstation-01`, services tab (coverage summary, services table with coverage and ports) | `03-macos-host-services-1440x900.png` | `03-macos-host-services.png` |
| macOS host `macos:workstation-01`, findings tab (vulnerabilities and misconfigurations) | `03-macos-host-findings-1440x900.png` | `03-macos-host-findings.png` |
| macOS host `macos:workstation-01`, events tab (24 h / 7 d / 30 d range, event-type facet) | `03-macos-host-events-1440x900.png` | `03-macos-host-events.png` |
| Ubuntu VM `linux:lab-vm-01`, overview tab (KPIs, telemetry sources, events by source, inventory, recent alerts, attributes, service coverage) | `04-linux-vm-overview-1440x900.png` | `04-linux-vm-overview.png` |
| Ubuntu VM `linux:lab-vm-01`, services tab (coverage summary, services table with coverage and ports) | `04-linux-vm-services-1440x900.png` | `04-linux-vm-services.png` |
| Ubuntu VM `linux:lab-vm-01`, findings tab (vulnerabilities and misconfigurations) | `04-linux-vm-findings-1440x900.png` | `04-linux-vm-findings.png` |
| Ubuntu VM `linux:lab-vm-01`, events tab (24 h / 7 d / 30 d range, event-type facet) | `04-linux-vm-events-1440x900.png` | `04-linux-vm-events.png` |
| kind cluster `k8s:extorq-lab`, overview tab (KPIs, telemetry sources, events by source, inventory, recent alerts, attributes, service coverage) | `05-kind-cluster-overview-1440x900.png` | `05-kind-cluster-overview.png` |
| kind cluster `k8s:extorq-lab`, workloads tab (Kubernetes levels, workloads and Kubernetes Services / Pods on the node) | `05-kind-cluster-workloads-1440x900.png` | `05-kind-cluster-workloads.png` |
| kind cluster `k8s:extorq-lab`, findings tab (vulnerabilities and misconfigurations) | `05-kind-cluster-findings-1440x900.png` | `05-kind-cluster-findings.png` |
| kind cluster `k8s:extorq-lab`, events tab (24 h / 7 d / 30 d range, event-type facet) | `05-kind-cluster-events-1440x900.png` | `05-kind-cluster-events.png` |
| Kubernetes node `extorq-lab-control-plane`, overview tab (KPIs, telemetry sources, events by source, inventory, recent alerts, attributes, service coverage) | `06-k8s-node-overview-1440x900.png` | `06-k8s-node-overview.png` |
| Kubernetes node `extorq-lab-control-plane`, workloads tab (Kubernetes levels, workloads and Kubernetes Services / Pods on the node) | `06-k8s-node-workloads-1440x900.png` | `06-k8s-node-workloads.png` |
| Kubernetes node `extorq-lab-control-plane`, findings tab (vulnerabilities and misconfigurations) | `06-k8s-node-findings-1440x900.png` | `06-k8s-node-findings.png` |
| Kubernetes node `extorq-lab-control-plane`, events tab (24 h / 7 d / 30 d range, event-type facet) | `06-k8s-node-events-1440x900.png` | `06-k8s-node-events.png` |
| GitHub repository `github:exigent07/extorq-lab`, overview tab (KPIs, telemetry sources, events by source, inventory, recent alerts, attributes, service coverage) | `07-github-repo-overview-1440x900.png` | `07-github-repo-overview.png` |
| GitHub repository `github:exigent07/extorq-lab`, findings tab (vulnerabilities and misconfigurations) | `07-github-repo-findings-1440x900.png` | `07-github-repo-findings.png` |
| GitHub repository `github:exigent07/extorq-lab`, events tab (24 h / 7 d / 30 d range, event-type facet) | `07-github-repo-events-1440x900.png` | `07-github-repo-events.png` |
| Host service `ssh` on the VM: header facts, coverage, figures, telemetry sources tab | `08-host-service-ssh-1440x900.png` | `08-host-service-ssh.png` |
| Host service `ssh`: ports and exposure tab (owner attribution with its basis) | `08-host-service-ssh-ports-1440x900.png` | `08-host-service-ssh-ports.png` |
| Kubernetes workload `kube-system/coredns`: header, coverage, telemetry tab | `09-k8s-workload-coredns-1440x900.png` | `09-k8s-workload-coredns.png` |
| Kubernetes workload `kube-system/coredns`: instances tab (Pods and containers) | `09-k8s-workload-coredns-instances-1440x900.png` | `09-k8s-workload-coredns-instances.png` |
| Kubernetes Service `kube-system/kube-dns` (unsupported: no adapter, shown so the gap stays visible) | `10-k8s-service-kube-dns-1440x900.png` | `10-k8s-service-kube-dns.png` |
| Kubernetes Service `kube-system/kube-dns`: ports tab | `10-k8s-service-kube-dns-ports-1440x900.png` | `10-k8s-service-kube-dns-ports.png` |
| Detections, Alerts tab: KPI row, alert history table with facets, range toggle | `11-detections-alerts-1440x900.png` | `11-detections-alerts.png` |
| Detections, Rules tab: rule health, runs, quiet sources, ATT&CK ids | `11-detections-rules-1440x900.png` | `11-detections-rules.png` |
| Investigation VM-001 SSH failure burst: Overview tab (why the rule fired, key signals: sequence stages, threshold checks, risk signals; grouped features; involved services) | `12-investigation-vm-001-overview-1440x900.png` | `12-investigation-vm-001-overview.png` |
| Investigation VM-001 SSH failure burst: Timeline tab (activity histogram per relationship lane, bursts with inline expanders, link strength) | `12-investigation-vm-001-timeline-1440x900.png` | `12-investigation-vm-001-timeline.png` |
| Investigation VM-001 SSH failure burst: Evidence tab (evidence table; rows open the detail sheet) | `12-investigation-vm-001-evidence-1440x900.png` | `12-investigation-vm-001-evidence.png` |
| Investigation VM-001 SSH failure burst: Correlation tab (relationship toggles, observations grouped by relationship, strength and event type) | `12-investigation-vm-001-correlation-1440x900.png` | `12-investigation-vm-001-correlation.png` |
| Investigation VM-001 SSH failure burst: AI tab (Jev triage and Gemini overview, advisory, provider flags from System health, evidence chips) | `12-investigation-vm-001-ai-1440x900.png` | `12-investigation-vm-001-ai.png` |
| Investigation VM-001 SSH failure burst: Context tab (one status per source, gap and missing-telemetry statements that agree, limitations, blind spots, posture summary) | `12-investigation-vm-001-context-1440x900.png` | `12-investigation-vm-001-context.png` |
| Investigation VM-002 systemd persistence: Overview tab (why the rule fired, key signals: sequence stages, threshold checks, risk signals; grouped features; involved services) | `13-investigation-vm-002-overview-1440x900.png` | `13-investigation-vm-002-overview.png` |
| Investigation VM-002 systemd persistence: Timeline tab (activity histogram per relationship lane, bursts with inline expanders, link strength) | `13-investigation-vm-002-timeline-1440x900.png` | `13-investigation-vm-002-timeline.png` |
| Investigation VM-002 systemd persistence: Evidence tab (evidence table; rows open the detail sheet) | `13-investigation-vm-002-evidence-1440x900.png` | `13-investigation-vm-002-evidence.png` |
| Investigation VM-002 systemd persistence: Correlation tab (relationship toggles, observations grouped by relationship, strength and event type) | `13-investigation-vm-002-correlation-1440x900.png` | `13-investigation-vm-002-correlation.png` |
| Investigation VM-002 systemd persistence: AI tab (Jev triage and Gemini overview, advisory, provider flags from System health, evidence chips) | `13-investigation-vm-002-ai-1440x900.png` | `13-investigation-vm-002-ai.png` |
| Investigation VM-002 systemd persistence: Context tab (one status per source, gap and missing-telemetry statements that agree, limitations, blind spots, posture summary) | `13-investigation-vm-002-context-1440x900.png` | `13-investigation-vm-002-context.png` |
| Investigation K8S-001 privileged Pod denied: Overview tab (why the rule fired, key signals: sequence stages, threshold checks, risk signals; grouped features; involved services) | `14-investigation-k8s-001-overview-1440x900.png` | `14-investigation-k8s-001-overview.png` |
| Investigation K8S-001 privileged Pod denied: Timeline tab (activity histogram per relationship lane, bursts with inline expanders, link strength) | `14-investigation-k8s-001-timeline-1440x900.png` | `14-investigation-k8s-001-timeline.png` |
| Investigation K8S-001 privileged Pod denied: Evidence tab (evidence table; rows open the detail sheet) | `14-investigation-k8s-001-evidence-1440x900.png` | `14-investigation-k8s-001-evidence.png` |
| Investigation K8S-001 privileged Pod denied: Correlation tab (relationship toggles, observations grouped by relationship, strength and event type) | `14-investigation-k8s-001-correlation-1440x900.png` | `14-investigation-k8s-001-correlation.png` |
| Investigation K8S-001 privileged Pod denied: AI tab (Jev triage and Gemini overview, advisory, provider flags from System health, evidence chips) | `14-investigation-k8s-001-ai-1440x900.png` | `14-investigation-k8s-001-ai.png` |
| Investigation K8S-001 privileged Pod denied: Context tab (one status per source, gap and missing-telemetry statements that agree, limitations, blind spots, posture summary) | `14-investigation-k8s-001-context-1440x900.png` | `14-investigation-k8s-001-context.png` |
| Investigation K8S-002 risky RBAC grant: Overview tab (why the rule fired, key signals: sequence stages, threshold checks, risk signals; grouped features; involved services) | `15-investigation-k8s-002-overview-1440x900.png` | `15-investigation-k8s-002-overview.png` |
| Investigation K8S-002 risky RBAC grant: Timeline tab (activity histogram per relationship lane, bursts with inline expanders, link strength) | `15-investigation-k8s-002-timeline-1440x900.png` | `15-investigation-k8s-002-timeline.png` |
| Investigation K8S-002 risky RBAC grant: Evidence tab (evidence table; rows open the detail sheet) | `15-investigation-k8s-002-evidence-1440x900.png` | `15-investigation-k8s-002-evidence.png` |
| Investigation K8S-002 risky RBAC grant: Correlation tab (relationship toggles, observations grouped by relationship, strength and event type) | `15-investigation-k8s-002-correlation-1440x900.png` | `15-investigation-k8s-002-correlation.png` |
| Investigation K8S-002 risky RBAC grant: AI tab (Jev triage and Gemini overview, advisory, provider flags from System health, evidence chips) | `15-investigation-k8s-002-ai-1440x900.png` | `15-investigation-k8s-002-ai.png` |
| Investigation K8S-002 risky RBAC grant: Context tab (one status per source, gap and missing-telemetry statements that agree, limitations, blind spots, posture summary) | `15-investigation-k8s-002-context-1440x900.png` | `15-investigation-k8s-002-context.png` |
| Investigation GH-001 workflow privilege escalation: Overview tab (why the rule fired, key signals: sequence stages, threshold checks, risk signals; grouped features; involved services) | `16-investigation-gh-001-overview-1440x900.png` | `16-investigation-gh-001-overview.png` |
| Investigation GH-001 workflow privilege escalation: Timeline tab (activity histogram per relationship lane, bursts with inline expanders, link strength) | `16-investigation-gh-001-timeline-1440x900.png` | `16-investigation-gh-001-timeline.png` |
| Investigation GH-001 workflow privilege escalation: Evidence tab (evidence table; rows open the detail sheet) | `16-investigation-gh-001-evidence-1440x900.png` | `16-investigation-gh-001-evidence.png` |
| Investigation GH-001 workflow privilege escalation: Correlation tab (relationship toggles, observations grouped by relationship, strength and event type) | `16-investigation-gh-001-correlation-1440x900.png` | `16-investigation-gh-001-correlation.png` |
| Investigation GH-001 workflow privilege escalation: AI tab (Jev triage and Gemini overview, advisory, provider flags from System health, evidence chips) | `16-investigation-gh-001-ai-1440x900.png` | `16-investigation-gh-001-ai.png` |
| Investigation GH-001 workflow privilege escalation: Context tab (one status per source, gap and missing-telemetry statements that agree, limitations, blind spots, posture summary) | `16-investigation-gh-001-context-1440x900.png` | `16-investigation-gh-001-context.png` |
| Investigation CORR-002 ordered HTTP -> SSH -> systemd sequence: Overview tab (why the rule fired, key signals: sequence stages, threshold checks, risk signals; grouped features; involved services) | `17-investigation-corr-002-overview-1440x900.png` | `17-investigation-corr-002-overview.png` |
| Investigation CORR-002 ordered HTTP -> SSH -> systemd sequence: Timeline tab (activity histogram per relationship lane, bursts with inline expanders, link strength) | `17-investigation-corr-002-timeline-1440x900.png` | `17-investigation-corr-002-timeline.png` |
| Investigation CORR-002 ordered HTTP -> SSH -> systemd sequence: Evidence tab (evidence table; rows open the detail sheet) | `17-investigation-corr-002-evidence-1440x900.png` | `17-investigation-corr-002-evidence.png` |
| Investigation CORR-002 ordered HTTP -> SSH -> systemd sequence: Correlation tab (relationship toggles, observations grouped by relationship, strength and event type) | `17-investigation-corr-002-correlation-1440x900.png` | `17-investigation-corr-002-correlation.png` |
| Investigation CORR-002 ordered HTTP -> SSH -> systemd sequence: AI tab (Jev triage and Gemini overview, advisory, provider flags from System health, evidence chips) | `17-investigation-corr-002-ai-1440x900.png` | `17-investigation-corr-002-ai.png` |
| Investigation CORR-002 ordered HTTP -> SSH -> systemd sequence: Context tab (one status per source, gap and missing-telemetry statements that agree, limitations, blind spots, posture summary) | `17-investigation-corr-002-context-1440x900.png` | `17-investigation-corr-002-context.png` |
| System health: collectors, ingestion spool, pipeline, rule execution, quarantine, AI providers | `18-system-health-1440x900.png` | `18-system-health.png` |
| Detections at 1024 px | `19-detections-1024x768.png` | `19-detections-1024.png` |
| CORR-002 investigation at 1024 px (rail below the tabs) | `19-investigation-corr-002-1024x768.png` | `19-investigation-corr-002-1024.png` |
| VM-001 evidence tab at 1024 px | `19-investigation-vm-001-evidence-1024x768.png` | `19-investigation-vm-001-evidence-1024.png` |
| Overview at 1024 px | `19-overview-1024x768.png` | `19-overview-1024.png` |
| VM-001 investigation on a phone (390 px) | `20-investigation-vm-001-390x844.png` | - |
| Ubuntu VM asset on a phone (390 px) | `20-linux-vm-390x844.png` | - |
| Overview on a phone (390 px): compact two-column KPI grid | `20-overview-390x844.png` | - |
| System health on a phone (390 px) | `20-system-health-390x844.png` | - |
| VM-001 evidence row opened in the detail sheet | `21-evidence-sheet-1440x900.png` | - |
| An alert id that does not exist: "Alert not found" with a way back (not a red failure) | `21-not-found-alert-1440x900.png` | - |
| An asset id that does not exist: "Asset not found" | `21-not-found-asset-1440x900.png` | - |

The six investigations are the demo alerts of `docs/demo-runbook.md`. The GitHub
mechanics-test repositories (`octocat/hello-world`, `actions/hello-world-javascript-action`)
are shown as the API reports them at capture time (stale until they retire 24 h after their
collector's last report; retired assets are then listed apart, collapsed, on the Assets page).
GitHub repositories have no Services tab (they carry no services). The Gemini overview button is
disabled with the reason while the AI settings disable Gemini (System health, AI providers).

Recapture (read-only; the password is read from a file and never printed). Pace the runs: the
API's ClickHouse read quota is shared.

```bash
export EXTORQ_SHOTS_PASSWORD_FILE=../var/secrets/analyst_password
node --experimental-websocket scripts/screenshots.mjs --base http://127.0.0.1:3000 \
  --out docs/screenshots --anon --first-screen 00-login-1440x900=/login
node --experimental-websocket scripts/screenshots.mjs --base http://127.0.0.1:3000 \
  --out docs/screenshots --first-screen --press Meta+k 01-command-palette-1440x900=/
# every other view: once with --first-screen (name-1440x900=/path), once without (name=/path)
node --experimental-websocket scripts/screenshots.mjs --base http://127.0.0.1:3000 \
  --out docs/screenshots --audit 01-overview=/ 02-assets=/assets 11-detections-alerts=/detections ...
EXTORQ_SHOTS_WIDTH=1024 EXTORQ_SHOTS_HEIGHT=768 node --experimental-websocket \
  scripts/screenshots.mjs --base http://127.0.0.1:3000 --out docs/screenshots 19-overview-1024=/
```

The pictures show lab asset names, simulation markers and the lab GitHub repository; they
contain no credentials. `docs/` is excluded from the console image (`.dockerignore`) and the
PNGs are not versioned (`.gitignore`).
