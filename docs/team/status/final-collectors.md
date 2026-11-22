# Collector release validation

Starting revision `023fdb63b6023143302a0733883c9749743835c3`, with the existing
uncommitted remediation and development changes retained.

| Area | Current implementation |
|---|---|
| Linux minimization | `infra/vm/files/extorq-collect-dispatch` 1.3.0 returns simple absolute executables from systemd `ExecStart`. The Linux collector also strips arguments from compatible older dispatcher replies and inventory tombstones. Reformatting a previously saved observation does not produce a systemd file-change event. |
| Dispatcher deployment | `infra/vm/vm.sh redeploy-dispatcher` prepares and checks the candidate before a same-directory atomic replacement. This action requires the verified, reachable ExtorQ VM and leaves its services running. |
| GitHub credentials | Dedicated fine-grained PAT file, collector ownership, 0600 or 0400, no token-value environment or CLI fallback. Repository scope and read-only grants are provisioned on GitHub. |
| GitHub delivery | Complete bounded workflow listing pages are fetched unconditionally. Missing tracked open runs are checked directly, including when a listing is truncated or transiently unavailable. The listing checkpoint advances only after a complete listing. |
| GitHub identity | New run-transition keys include attempt, status, conclusion and native revision when present. Old persisted run checkpoints load without re-emitting the same state. Older events already stored retain their identities. Upstream states between polls and re-runs of completed runs outside the listing window remain source limits. |

| Executed check | Result |
|---|---|
| `UV_CACHE_DIR=/tmp/extorq-a6-uv uv run --no-sync pytest tests/unit/github tests/unit/linux tests/rules/test_gh001_collector_contract.py -q` | 334 passed. Four GitHub-to-ClickHouse contract executions skipped because the Docker API was inaccessible. GitHub API tests used synthetic responses. |
| `UV_CACHE_DIR=/tmp/extorq-a6-uv uv run --no-sync ruff check collectors/src/extorq_collectors/github collectors/src/extorq_collectors/linux collectors/src/extorq_collectors/sdk/config.py tests/unit/github tests/unit/linux` | Passed. |
| `UV_CACHE_DIR=/tmp/extorq-a6-uv uv run --no-sync mypy collectors/src/extorq_collectors/github collectors/src/extorq_collectors/linux` | Passed in 36 source files. |
| `bash -n infra/vm/vm.sh` and local `SSH_ORIGINAL_COMMAND=version .venv/bin/python -I infra/vm/files/extorq-collect-dispatch` | Shell syntax passed. The dispatcher returned 1.3.0, protocol 1. |
| Direct TCP connection to VM SSH `127.0.0.1:2222` | Permission error (`Errno 1`). VM status could not establish running state. Rollout and current Linux source delivery remain unverified. |
| Metadata check of configured `var/secrets/github/readonly-pat` | File absent. Private-repository grants, API coverage and live delivery remain unverified. |

See the [VM runbook](../../../infra/vm/README.md) for the restricted-account version check
and the [GitHub telemetry guide](../../telemetry/github.md#provision-the-dedicated-token)
for required repository permissions and token provisioning.
