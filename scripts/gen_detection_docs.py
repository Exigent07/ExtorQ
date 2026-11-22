#!/usr/bin/env python3
# ruff: noqa: E501  (the manual shell steps are long literal blocks)
"""Generate docs/detection-tests.md from the rule files and the test specs.

Everything factual (what a rule detects, thresholds, ATT&CK ids, false positives, blind spots,
the automated action / control / cleanup of each test) is read from ``rules/*/*.yaml`` and
``detection_tests`` so the document cannot drift from the code. The only hand-written part is
MANUAL below: the exact shell steps to trigger each detection yourself.

    uv run python scripts/gen_detection_docs.py [--report var/reports/detection-tests-<ts>.json]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from detection_tests.matrix import build_suites  # noqa: E402

OUT = REPO / "docs" / "detection-tests.md"

PREAMBLE = r"""
## 0. Setup for the manual steps

Run everything from the repository root with the stack up (`make up-full`), the VM up
(`make vm-up`), the cluster up (`make kind-up`) and the collectors running
(`make collectors-start`). For ~1-minute detection times switch on the fast profile first
(`make fast-on`, revert with `make fast-off`).

```bash
export ID=$(openssl rand -hex 3)          # artefacts are named extorq-test-$ID so they are easy to find and remove
vm() { ssh -i var/vm/keys/extorq-admin -p 2222 -o BatchMode=yes -o IdentitiesOnly=yes \
          -o UserKnownHostsFile=var/vm/known_hosts extorq-admin@127.0.0.1 "$@"; }
K="kubectl --kubeconfig var/kube/extorq-lab-admin.kubeconfig --context kind-extorq-lab"
api() { curl -s -H "Authorization: Bearer $(cat var/secrets/api_service_token)" \
          -H 'X-ExtorQ-User: me' -H 'X-ExtorQ-Role: viewer' "http://127.0.0.1:8000$1"; }
# newest alerts of a rule (id, asset, first/last seen, evidence count):
alerts() { api "/api/v1/alerts?rule_id=$1&limit=3" | python3 -c \
  "import sys,json; [print(a['alert_id'], a['asset_id'], a['first_seen'], a['event_count'], a['confidence']) for a in json.load(sys.stdin)['items']]"; }
# the evidence of one alert (must resolve to stored events; unresolved ids are listed separately):
evidence() { api "/api/v1/alerts/$1" | python3 -c \
  "import sys,json; d=json.load(sys.stdin); print(len(d['evidence']),'evidence events; unresolved:',d['unresolved_evidence_ids']); [print(' ',e['event_time'],e['event_type'],e['source_type']) for e in d['evidence'][:8]]"; }
```

Each test below says **how long to wait**. If you repeat a test right after a previous run, the
rule's earlier alert can still be open (see *Episodes* in section 1): new activity is then merged
into it instead of creating a new alert, so wait for the episode to close or look at the existing
alert's `last_seen`.
"""

HOW_IT_WORKS = r"""
## 1. How a detection happens (applies to every test)

```
real activity ─► source (journald/auditd/audit log/GitHub API/unified log) ─► collector ─► gateway (TLS, token)
   ─► durable spool ─► writer ─► ClickHouse `events` ─► detector (runs each rule's SQL on a schedule)
   ─► `alerts` + `alert_evidence` ─► correlation builds an InvestigationContext ─► Jev advisory triage ─► console/API
```

* **Nothing is marked.** The tests perform the real action and are verified by asset + rule + time
  window; the telemetry carries no test marker. The detector treats it like any other activity.
* **Rules are deterministic SQL** over normalised events (`rules/<domain>/<ID>.sql`). Thresholds,
  windows and allowlists live in the rule's YAML `params`; the alert's `confidence` is computed
  from how complete the evidence is (for example two independent sources agreeing), never from AI.
* **Latency = source + collector + pipeline + detector.** With the default configuration an alert
  appears 1-5 minutes after the activity (collectors poll every 30-120 s, rules run every 60-120 s).
  The fast profile (`make fast-on`) polls every 10-15 s and runs rules every 10 s, so Linux,
  Kubernetes and macOS alerts appear in about 50-70 s and GitHub in 80-100 s (it polls an external
  API). A rule's window (for example 5 minutes for VM-001) is how far back it looks; it does not
  delay the alert.
* **Episodes.** Window-bucket rules merge activity into one alert while it keeps continuing (for
  example 15 minutes for K8S-003/K8S-004). A repeat inside that period extends the existing
  alert (`last_seen` moves) instead of creating a new one. This is intended: one burst, one alert.
* **Negative controls.** Every test also performs similar-looking benign activity that must NOT
  alert, and the runner proves the rule actually evaluated that activity (a rule run started after
  the control's telemetry was stored) before it accepts silence. A control that produces no
  telemetry cannot prove anything and is reported *inconclusive*, never a pass.
* **Shared NAT address.** Everything the Mac sends to the VM arrives from `10.0.2.2` (QEMU's NAT).
  Rules that group by source address therefore report confidence **medium/low**: the burst is real
  but its origin is not attributable. That is deliberate honesty, not a defect.
"""

# (asset key, rule id) -> dict(steps=..., wait=..., see=...)
MANUAL: dict[tuple[str, str], dict[str, str]] = {
    ("linux", "VM-001"): dict(
        wait="~1 min with the fast profile",
        steps=r"""
```bash
KD=$(mktemp -d); for i in 0 1 2 3 4; do ssh-keygen -q -t ed25519 -N '' -C '' -f $KD/id_$i; done
S="ssh -p 2222 -o BatchMode=yes -o IdentitiesOnly=yes -o PreferredAuthentications=publickey \
   -o StrictHostKeyChecking=yes -o UserKnownHostsFile=var/vm/known_hosts -o ConnectTimeout=8"
for n in 1 2; do for u in root admin oracle test ubuntu; do $S -i $KD/id_0 $u@127.0.0.1 true 2>/dev/null; sleep 0.3; done; done
$S -i $KD/id_1 -i $KD/id_2 -i $KD/id_3 -i $KD/id_4 admin@127.0.0.1 true 2>/dev/null   # exceeds MaxAuthTries 3
rm -rf $KD                                       # cleanup: nothing exists on the VM
```
The keys are generated for this run and authorised nowhere, so every attempt fails.
""",
        see="`alerts VM-001` shows `src_ip 10.0.2.2`, confidence **medium**; the evidence has the sshd `invalid_user` / `preauth_closed` / `max_auth_exceeded` events.",
    ),
    ("linux", "VM-002"): dict(
        wait="~1 min",
        steps=r"""
```bash
vm "sudo tee /etc/systemd/system/extorq-test-$ID.service >/dev/null" <<'UNIT'
[Unit]
Description=Nightly cache warm-up

[Service]
Type=oneshot
ExecStart=/bin/true

[Install]
WantedBy=multi-user.target
UNIT
vm "sudo systemctl daemon-reload && sudo systemctl enable extorq-test-$ID.service"   # never started
# negative control: a state change without a unit file change
vm "sudo systemctl restart cron.service"
# cleanup
vm "sudo systemctl disable extorq-test-$ID.service; sudo rm -f /etc/systemd/system/extorq-test-$ID.service; sudo systemctl daemon-reload"
```
""",
        see="Alert for `/etc/systemd/system/extorq-test-$ID.service`. Confidence **high** when the auditd write and the inventory diff agree on the path (two independent sources).",
    ),
    ("linux", "VM-003"): dict(
        wait="~1 min",
        steps=r"""
```bash
vm "sudo useradd --no-create-home --shell /usr/sbin/nologin --comment 'Build agent' extorq-test-$ID"
# cleanup (the removal is also the negative control: removal must NOT alert)
vm "sudo userdel extorq-test-$ID; sudo groupdel extorq-test-$ID 2>/dev/null; getent passwd extorq-test-$ID || echo removed"
```
""",
        see="Alert naming the new account (inventory diff of /etc/passwd, corroborated by auditd identity-file writes).",
    ),
    ("linux", "VM-004"): dict(
        wait="~1 min",
        steps=r"""
```bash
vm "sudo tee /etc/cron.d/extorq-test-$ID >/dev/null" <<'CRON'
# Rotate application cache
SHELL=/bin/sh
PATH=/usr/sbin:/usr/bin:/sbin:/bin
17 3 1 1 * root /bin/true
CRON
vm "sudo rm -f /etc/cron.d/extorq-test-$ID"    # cleanup (the removal is the negative control)
```
The job runs `/bin/true` once a year, so nothing runs during the test.
""",
        see="Alert for the added `/etc/cron.d` file (inventory diff + auditd write).",
    ),
    ("linux", "HTTP-001"): dict(
        wait="~1 min",
        steps=r"""
```bash
for p in /.env /.git/config /wp-login.php /phpmyadmin/ /server-status /admin /actuator/health \
         /.aws/credentials /config.php /backup.zip /cgi-bin/test.cgi /xmlrpc.php /.svn/entries /jenkins/login; do
  curl -s -o /dev/null -w "%{http_code} $p\n" http://127.0.0.1:8088$p
done                                              # at least 12 must be 4xx
# negative control: ordinary traffic
for i in $(seq 10); do curl -s -o /dev/null http://127.0.0.1:8088/; curl -s -o /dev/null http://127.0.0.1:8088/healthz; done
```
""",
        see="Alert from `10.0.2.2` with the probe routes listed; evidence is the nginx `http.request` events (journald).",
    ),
    ("linux", "APP-001"): dict(
        wait="~1 min",
        steps=r"""
```bash
for i in 1 2 3 4 5 6; do
  curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:8088/login \
       -H 'Content-Type: application/json' -d "{\"username\":\"lab-admin\",\"password\":\"wrong-$RANDOM\"}"
done                                              # each answers 401
```
The negative control (one successful login) is performed *inside* the VM so the demo credential never leaves it.
""",
        see="Alert variant *guessing* for user `lab-admin` (6 `app.auth.login_failed` events from the portal's JSON log).",
    ),
    ("linux", "CORR-002"): dict(
        wait="~2-3 min, and it needs **30 quiet minutes** (no HTTP probing/SSH bursts) before it starts",
        steps=r"""
Run the three stages **in this order within a few minutes**, as one story:

1. HTTP probing (the HTTP-001 commands above)
2. an SSH failure burst (the VM-001 commands above)
3. a systemd persistence change (the VM-002 commands above, but leave the unit in place until the alert appears)

Negative control (run it first, alone): only the SSH burst, with no probing in the previous 30 minutes.
""",
        see="CORR-002 at **low** confidence (all stages share the NAT address, so it is ordered co-occurrence, never causation); HTTP-001, VM-001 and VM-002 alert as well.",
    ),
    ("kubernetes", "K8S-001"): dict(
        wait="~1 min",
        steps=r"""
```bash
cat <<EOF | $K create -f -          # EXPECTED: Error ... forbidden: violates PodSecurity "baseline:latest"
apiVersion: v1
kind: Pod
metadata: {name: extorq-test-$ID, namespace: extorq-restricted}
spec:
  hostPID: true
  automountServiceAccountToken: false
  restartPolicy: Never
  nodeSelector: {kubernetes.io/hostname: extorq-test-unscheduled}   # can never be scheduled
  containers:
  - {name: worker, image: "alpine:3.19", command: ["sleep","300"], securityContext: {privileged: true}}
EOF
```
The API server refuses it (HTTP 403), so no pod exists and nothing needs cleanup. Negative control: the same pod without `privileged`/`hostPID` and with a restricted securityContext is admitted (201); delete it afterwards.
""",
        see="Alert from the kube-apiserver **audit log** (shipped by the OTel DaemonSet): verb `create`, resource `pods`, response code **403**, the PodSecurity violation text. One alert per audit id.",
    ),
    ("kubernetes", "K8S-002"): dict(
        wait="~1 min",
        steps=r"""
```bash
$K -n extorq-apps create serviceaccount extorq-test-$ID
$K create clusterrolebinding extorq-test-$ID --clusterrole=cluster-admin --serviceaccount=extorq-apps:extorq-test-$ID
# negative control: a read-only grant is not risky
$K -n extorq-apps create serviceaccount extorq-test-ro-$ID
$K -n extorq-apps create rolebinding extorq-test-ro-$ID --clusterrole=view --serviceaccount=extorq-apps:extorq-test-ro-$ID
# cleanup
$K delete clusterrolebinding extorq-test-$ID; $K -n extorq-apps delete rolebinding,serviceaccount extorq-test-ro-$ID; $K -n extorq-apps delete serviceaccount extorq-test-$ID
```
""",
        see="Alert for the ClusterRoleBinding, flag `cluster_admin`. Confidence **high** when the audit write and the inventory diff agree on the **same object UID and resource version**.",
    ),
    ("kubernetes", "K8S-003"): dict(
        wait="~1 min (repeat runs: wait out the 15-minute episode)",
        steps=r"""
```bash
$K -n extorq-apps exec deploy/lab-portal -- id             # interactive exec by a human identity
# negative control: reading logs is not exec
$K -n extorq-apps logs deploy/lab-portal --tail=5 >/dev/null
```
""",
        see="Alert naming the pod, container and the human user (system components and service accounts are excluded). The audit log shows that an exec session was opened, **not** what ran inside it.",
    ),
    ("kubernetes", "K8S-004"): dict(
        wait="~1 min (repeat runs: wait out the 15-minute episode)",
        steps=r"""
```bash
$K get secrets -A -o name >/dev/null                        # cluster-wide enumeration (output discarded)
# negative control: one object, one namespace
$K -n extorq-apps get configmap kube-root-ca.crt >/dev/null
```
""",
        see="Alert for a cluster-wide `list` of secrets by a non-system identity. Secret *values* never appear in the audit metadata or in ExtorQ.",
    ),
    ("kubernetes", "K8S-005"): dict(
        wait="~1 min",
        steps=r"""
```bash
$K create namespace extorq-test-$ID                           # no Pod Security labels => nothing is enforced
cat <<EOF | $K create -f -        # ADMITTED (201): privileged pod, never scheduled
apiVersion: v1
kind: Pod
metadata: {name: extorq-test-$ID, namespace: extorq-test-$ID}
spec:
  automountServiceAccountToken: false
  restartPolicy: Never
  nodeSelector: {kubernetes.io/hostname: extorq-test-unscheduled}
  containers:
  - {name: worker, image: "alpine:3.19", command: ["sleep","300"], securityContext: {privileged: true}}
EOF
$K delete namespace extorq-test-$ID --wait=true             # cleanup (deletes the pod too)
```
Negative control: an unprivileged, restricted-compliant pod in the same namespace.
""",
        see="Alert for the **admitted** privileged pod (the opposite case of K8S-001, where admission refused it).",
    ),
    ("kubernetes", "APP-001"): dict(
        wait="~1 min",
        steps=r"""
```bash
for i in 1 2 3 4 5 6; do
  curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:8089/login \
       -H 'Content-Type: application/json' -d "{\"username\":\"lab-admin\",\"password\":\"wrong-$RANDOM\"}"
done
```
(8089 is the NodePort of the in-cluster web app.) Evidence comes from the container's JSON log shipped by OTel.
""",
        see="Alert variant *guessing* on `k8s:extorq-lab` with the pod/workload attribution.",
    ),
    ("github", "GH-001"): dict(
        wait="~1.5 min (the GitHub collector polls an external API)",
        steps=r"""
```bash
git clone -q https://github.com/Exigent07/extorq-lab var/github/extorq-lab 2>/dev/null || git -C var/github/extorq-lab pull -q
cd var/github/extorq-lab
python3 - <<'PY'
import re, pathlib
p = pathlib.Path(".github/workflows/ci.yml"); s = p.read_text()
p.write_text(re.sub(r"^permissions:\n  contents: read\n", "permissions: write-all\n", s, count=1, flags=re.M))
PY
git commit -qam "ci: release automation permissions [skip ci]" && git push -q
# cleanup
git revert --no-edit HEAD && git push -q; cd - >/dev/null
```
Negative control: change `permissions` to `{}` at workflow level with `contents: read` only on the job (reduces privileges).
""",
        see="Alert on the commit: `permissions_before = contents:read`, `permissions_after = write-all`, 14 added write scopes, confidence **high**. The revert and the permission-reducing commit must not alert.",
    ),
    ("github", "GH-002"): dict(
        wait="~1.5 min",
        steps=r"""
```bash
cd var/github/extorq-lab && git pull -q
cat > .github/workflows/extorq-test-$ID-pr-preview.yml <<'YAML'
name: PR preview
on:
  pull_request_target:
    types: [opened, synchronize]
permissions:
  contents: read
jobs:
  preview:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          allow-unsafe-pr-checkout: true
          persist-credentials: false
      - run: git log -1 --format='%H'
YAML
git add -A && git commit -qm "ci: add PR preview workflow [skip ci]" && git push -q
git revert --no-edit HEAD && git push -q; cd - >/dev/null          # cleanup
```
Negative control: the same file on `pull_request` (not `_target`) checking out the default ref.
""",
        see="Alert: privileged trigger `pull_request_target` **plus** a checkout of the untrusted PR head. GH-001 also alerts (a privileged trigger was added): a documented overlap. It only runs when a pull request is opened, which nobody does here.",
    ),
    ("github", "GH-003"): dict(
        wait="~1.5 min",
        steps=r"""
```bash
cd var/github/extorq-lab && git pull -q
cat > .github/workflows/extorq-test-$ID-image-build.yml <<'YAML'
name: Container image
on: workflow_dispatch
permissions:
  contents: read
jobs:
  image:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with: {persist-credentials: false}
      - uses: docker/setup-buildx-action@v3          # third-party action pinned by TAG, not by commit SHA
      - run: docker buildx build --load -t extorq-lab:ci .
YAML
git add -A && git commit -qm "ci: add image build [skip ci]" && git push -q
git revert --no-edit HEAD && git push -q; cd - >/dev/null          # cleanup
```
Negative control: the same action pinned to its full 40-hex commit SHA (first-party `actions/*` is never third-party).
""",
        see="Alert naming `docker/setup-buildx-action@v3`.",
    ),
    ("github", "GH-004"): dict(
        wait="~1.5 min",
        steps=r"""
```bash
cd var/github/extorq-lab && git pull -q
cat > .github/workflows/extorq-test-$ID-issue-triage.yml <<'YAML'
name: Issue triage
on:
  issues:
    types: [opened]
permissions:
  contents: read
jobs:
  triage:
    runs-on: ubuntu-24.04
    steps:
      - name: Print the issue title
        run: |
          echo "New issue: ${{ github.event.issue.title }}"
YAML
git add -A && git commit -qm "ci: add issue triage [skip ci]" && git push -q
git revert --no-edit HEAD && git push -q; cd - >/dev/null          # cleanup
```
Negative control: pass the title through `env: ISSUE_TITLE: ${{ ... }}` and use `"$ISSUE_TITLE"` in the shell. The workflow must be **valid YAML** (a `run:` value containing `: ` must be a block scalar as above) or the analyser, correctly, refuses to parse it.
""",
        see="Alert naming the injectable expression `${{ github.event.issue.title }}`. It runs only when an issue is opened.",
    ),
    ("github", "GH-005"): dict(
        wait="~1.5 min",
        steps=r"""
```bash
cd var/github/extorq-lab && git pull -q && mkdir -p deploy
{ echo '# Staging deployment settings'; echo 'AWS_REGION=eu-central-1'
  printf 'AWS_ACCESS_KEY_ID=AKIA%s\n' "$(LC_ALL=C tr -dc 'A-Z2-7' </dev/urandom | head -c16)"
  printf 'AWS_SECRET_ACCESS_KEY=%s\n' "$(LC_ALL=C tr -dc 'A-Za-z0-9/+' </dev/urandom | head -c40)"; } > deploy/extorq-test-$ID.env
git add -A && git commit -qm "deploy: add staging settings [skip ci]" && git push -q
git revert --no-edit HEAD && git push -q; cd - >/dev/null          # cleanup (the values stay in git history)
```
These are random, AWS-**shaped** strings, not real keys. Negative control: commit a `sha256sum` line (high entropy, not a credential).
""",
        see="Alert with patterns `aws_access_key` / `aws_secret_key`. **Only the pattern name, file, line and a redacted match are stored; the value never is.**",
    ),
    ("macos", "MAC-001"): dict(
        wait="~1 min",
        steps=r"""
```bash
L=com.extorq.test.$ID
cat > ~/Library/LaunchAgents/$L.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$L</string>
  <key>ProgramArguments</key><array><string>/usr/bin/true</string></array>
  <key>RunAtLoad</key><false/>
</dict></plist>
EOF
plutil -lint ~/Library/LaunchAgents/$L.plist
# NEVER run launchctl load/bootstrap. Cleanup (the removal is also the negative control):
rm -f ~/Library/LaunchAgents/$L.plist
```
macOS may show a "Background Items Added" notification.
""",
        see="Alert for the new plist path (`persistence.launchd.item_created`, user scope). The removal event is reported but must not alert.",
    ),
    ("macos", "MAC-002"): dict(
        wait="~1 min",
        steps=r"""
```bash
L=com.extorq.test.sh$ID
cat > ~/Library/LaunchAgents/$L.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$L</string>
  <key>ProgramArguments</key><array><string>/bin/sh</string><string>-c</string><string>/tmp/extorq-test-$ID</string></array>
  <key>RunAtLoad</key><false/>
</dict></plist>
EOF
rm -f ~/Library/LaunchAgents/$L.plist      # cleanup; never launchctl load
```
Negative control: the same plist running `/usr/bin/true` (raises MAC-001 only). The script path does not exist and the agent is never loaded.
""",
        see="Alert for a launch item that starts a shell/interpreter or runs from a user-writable path; MAC-001 alerts too (documented overlap).",
    ),
    ("macos", "MAC-003"): dict(
        wait="~1 min",
        steps=r"""
```bash
PORT=$((42000 + RANDOM % 7000))
python3 - $PORT <<'PY' &
import socket, sys, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", int(sys.argv[1]))); s.listen(5); s.settimeout(1); end = time.time() + 120
while time.time() < end:
    try: c, _ = s.accept(); c.close()
    except socket.timeout: pass
PY
LPID=$!; sleep 90; kill $LPID                 # cleanup: stop the listener
```
Negative control: the same listener bound to `127.0.0.1`.
""",
        see="Alert naming the port and the process (`python3`), because a non-allowlisted executable listens on all interfaces. Needs the listener to exist for at least one inventory scan.",
    ),
    ("macos", "MAC-004"): dict(
        wait="~1 min",
        steps=r"""
```bash
sudo -k
for i in 1 2 3; do echo "wrong-$RANDOM" | sudo -k -S -v 2>/dev/null; done   # three wrong passwords; no privilege is ever obtained
sudo -k                                                                      # cleanup: drop any cached timestamp
```
Negative control: a single failed attempt (below the threshold). You will not be prompted: `-S` reads the (wrong) password from the pipe.
""",
        see="Alert for the current user: three `auth.sudo.failure` events from the unified log within the rule window.",
    ),
    ("macos", "MAC-005"): dict(
        wait="~1 min",
        steps=r"""
```bash
A="/Applications/ExtorQ Test.app"; mkdir -p "$A/Contents/MacOS"
cat > "$A/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>com.extorq.test.$ID</string>
  <key>CFBundleName</key><string>ExtorQ Test</string>
  <key>CFBundleExecutable</key><string>extorq-test</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>1.0.0</string>
</dict></plist>
EOF
printf '#!/bin/sh\nexit 0\n' > "$A/Contents/MacOS/extorq-test"; chmod +x "$A/Contents/MacOS/extorq-test"
codesign --verify --strict "$A" || echo "unsigned (expected)"
rm -rf "$A"                                            # cleanup; the app is never executed
```
Negative control: copy a small **signed third-party** app (not an Apple system app: SIP forbids copying those) under another name and delete it afterwards.
""",
        see="Alert naming the bundle path, with `signed=false`. Installation and execution are different things; nothing here runs.",
    ),
}


def load_rules() -> dict[str, dict]:
    out = {}
    for f in sorted((REPO / "rules").glob("*/*.yaml")):
        d = yaml.safe_load(f.read_text())
        out[d["rule_id"]] = d
    return out


def collapse(text: object) -> str:
    return " ".join(str(text or "").split())


def timings(report: Path | None) -> dict[tuple[str, str], str]:
    if report is None or not report.exists():
        return {}
    data = json.loads(report.read_text())
    out: dict[tuple[str, str], str] = {}
    for t in data.get("tests", []):
        m = re.search(
            r"found (\d+)s after the action", (t.get("positive") or {}).get("message") or ""
        )
        key = (t["asset_id"].split(":")[0], t["rule_id"])
        out[key] = f"{m.group(1)} s" if m else "n/a"
    return out


def newest_batch_report() -> Path | None:
    best = None
    for f in (REPO / "var" / "reports").glob("detection-tests-*.json"):
        try:
            d = json.loads(f.read_text())
        except (OSError, ValueError):
            continue
        if len(d.get("tests", [])) >= 20 and (
            best is None or f.stat().st_mtime > best.stat().st_mtime
        ):
            best = f
    return best


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", type=Path, default=None)
    args = ap.parse_args()
    report = (REPO / args.report).resolve() if args.report else newest_batch_report()
    latency = timings(report)
    rules = load_rules()
    lines: list[str] = [
        "# Detection tests: what fires, why, and how to trigger it",
        "",
        "_Generated by `scripts/gen_detection_docs.py` from `rules/` and `detection_tests/`; the "
        "manual steps are the only hand-written part. Re-generate after changing a rule or a test._",
        "",
        "Every test below is **real activity on a monitored asset**, not an inserted record: the "
        "telemetry travels the normal path and the rule that fires is the production rule. "
        "Run them all with `make test-detections` (after `make fast-on`), or one asset with "
        "`make test-detections-linux|kubernetes|github|macos`, CORR-002 with "
        "`make test-detections-corr`.",
        "",
        HOW_IT_WORKS.strip(),
        "",
        PREAMBLE.strip(),
        "",
    ]
    if report:
        lines += [
            "## Results of the reference run",
            "",
            f"Report: `{report.relative_to(REPO)}`. Time from the attack to the alert being found "
            "(poll granularity 10 s, fast profile):",
            "",
            "| Asset | Rule | Captured after the action |",
            "|---|---|---|",
        ]
        for (asset, rule), value in sorted(latency.items()):
            lines.append(f"| {asset} | {rule} | {value} |")
        lines.append("")
    suites = build_suites(REPO, "all")
    n = 1
    for suite in suites:
        lines += [f"## {n + 1}. {suite.asset.label} (`{suite.asset.asset_id}`)", ""]
        n += 1
        for test in suite.tests:
            sp = test.spec
            rule = rules.get(sp.rule_id, {})
            manual = MANUAL.get((suite.asset.key, sp.rule_id), {})
            params = rule.get("params") or {}
            lines += [
                f"### {sp.rule_id}: {sp.title}",
                "",
                f"* **Rule** `{sp.rule_id}` v{rule.get('version', '?')}, severity **{rule.get('severity', '?')}**, "
                f"ATT&CK {', '.join(rule.get('mitre_techniques') or []) or 'n/a'}, "
                f"runs every {(rule.get('schedule') or {}).get('interval_seconds', '?')} s "
                f"(look-back {(rule.get('schedule') or {}).get('lookback_seconds', '?')} s), "
                f"dedup `{(rule.get('dedup') or {}).get('strategy', '?')}`"
                + (
                    f" ({rule['dedup']['bucket_seconds']} s buckets)"
                    if (rule.get("dedup") or {}).get("bucket_seconds")
                    else ""
                )
                + ".",
                "* **Telemetry it needs:** "
                + "; ".join(
                    f"`{r['source_type']}` → {', '.join('`' + e + '`' for e in r['event_types'])}"
                    for r in rule.get("requires", [])
                )
                + ".",
                "",
                "**Why it fires.** " + collapse(rule.get("description")),
                "",
            ]
            if params:
                shown = {k: v for k, v in params.items() if not isinstance(v, list) or len(v) <= 8}
                lines += [
                    "**Thresholds / parameters** (`params` in the rule YAML): `"
                    + json.dumps(shown, separators=(",", ":"))[:500]
                    + "`",
                    "",
                ]
            lines += [
                f"**What the automated test does** (`detection_tests`, test id `{sp.test_id}`)",
                "",
                f"* Positive: {sp.positive}",
                f"* Negative control (must NOT alert): {sp.negative}",
                f"* Cleanup: {sp.cleanup}",
                f"* Expected: {sp.expected_alert}",
                f"* Why it is safe: {sp.safety}",
                f"* Evidence source and wait: {sp.source.description}",
                "",
            ]
            if manual:
                lines += [
                    f"**Trigger it yourself** (wait: {manual['wait']})",
                    "",
                    manual["steps"].strip(),
                    "",
                    f"**What you should see.** {manual['see']}",
                    "",
                ]
            fp = rule.get("false_positives") or []
            blind = rule.get("blind_spots") or []
            if fp:
                lines += (
                    ["**False positives considered:**", ""]
                    + [f"* {collapse(x)}" for x in fp]
                    + [""]
                )
            if blind:
                lines += (
                    ["**Blind spots (what this rule cannot see):**", ""]
                    + [f"* {collapse(x)}" for x in blind]
                    + [""]
                )
    OUT.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(REPO)} ({OUT.stat().st_size // 1024} KiB, {len(suites)} assets)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
