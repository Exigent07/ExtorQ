"""Generate the SYNTHETIC GH-001 collector fixtures in tests/fixtures/github/.

* ``gh001_collector_output.jsonl``: baseline commit, escalation commit
  (``[extorq-sim gh001fixture]``) and cleanup commit, all parseable (structured analysis).
* ``gh001_lexical_fallback.jsonl``: the same scenario, but the escalation version of the
  workflow is padded beyond the analyser's 512 KiB budget, so the collector cannot parse it
  and compares it lexically (``attributes.analysis = "lexical_fallback"``,
  ``effective_permissions_unknown = true``; run marker ``[extorq-sim gh001lexical]``).

The GitHub API is the synthetic fake from tests/unit/github/github_fakes.py (owner
``example-org``, logins ``synthetic-*``); the workflow files are the real lab baseline
(lab/github-repo/.github/workflows/ci.yml) and the GH-001 template
(simulations/github/templates/ci-gh001.yml). The events are produced by the real
collector code path (RepoPoller -> workflow analyser -> EventBuilder), so the fixtures show
exactly what the GitHub collector emits. Every event is labelled ``extorq.fixture=synthetic``.

Run from the repository root:
    uv run python tests/fixtures/github/generate_gh001_fixture.py
"""

from __future__ import annotations

import json
import sys
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tests/unit/github"))

from github_fakes import FakeGitHub  # noqa: E402

from extorq.contracts import SecurityEvent  # noqa: E402
from extorq_collectors.github.client import GitHubClient  # noqa: E402
from extorq_collectors.github.config import GitHubCollectorConfig  # noqa: E402
from extorq_collectors.github.poller import RepoPoller  # noqa: E402
from extorq_collectors.github.state import RepoState  # noqa: E402
from extorq_collectors.github.workflow import MAX_WORKFLOW_BYTES  # noqa: E402

CI = ".github/workflows/ci.yml"
HERE = Path(__file__).parent
#: Comment padding that makes a valid workflow exceed the analyser's size budget.
PADDING = "# synthetic padding beyond the analyser budget\n" * (MAX_WORKFLOW_BYTES // 47 + 64)


def scenario(escalated: str, marker: str, *, sha_salt: str = "") -> list[SecurityEvent]:
    lab = (ROOT / "lab/github-repo" / CI).read_text(encoding="utf-8")
    fake = FakeGitHub(sha_salt=sha_salt)
    cfg = GitHubCollectorConfig.from_mapping({"repos": [fake.full_name]})
    client = GitHubClient("ghp_" + "F" * 36, transport=fake.transport(), sleep=lambda _s: None)
    state_json: list[str | None] = [None]
    events: list[SecurityEvent] = []

    def emit(records: list, state: RepoState) -> None:  # type: ignore[type-arg]
        state_json[0] = state.to_json()
        events.extend(r.data for r in records if isinstance(r.data, SecurityEvent))

    def poll() -> None:
        when = fake.clock + timedelta(minutes=1)
        RepoPoller(
            client=client,
            repo_cfg=cfg.repos[0],
            cfg=cfg,
            collector_id="github-repos",
            producer_id="github-collector",
            state=RepoState.from_json(state_json[0]),
            emit=emit,
            clock=lambda: when,
        ).poll()

    fake.commit("Initial commit: ExtorQ lab inventory service", {CI: lab, "README.md": "lab\n"})
    poll()
    fake.commit(
        f"ci: add PR preview job and broaden token permissions [extorq-sim {marker}]",
        {CI: escalated},
        pusher="synthetic-operator",
    )
    poll()
    fake.commit(f"ci: restore least-privilege CI workflow [extorq-sim {marker} cleanup]", {CI: lab})
    poll()
    return events


def write(events: list[SecurityEvent], name: str) -> None:
    wanted = {"github.commit.observed", "github.workflow.modified"}
    lines = []
    for event in events:
        if event.event_type in wanted:
            labelled = event.model_copy(update={"labels": {"extorq.fixture": "synthetic"}})
            lines.append(json.dumps(labelled.model_dump(mode="json"), sort_keys=True))
    out = HERE / name
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {len(lines)} events to {out.relative_to(ROOT)}")


def main() -> int:
    gh001 = (ROOT / "simulations/github/templates/ci-gh001.yml").read_text(encoding="utf-8")
    write(scenario(gh001, "gh001fixture"), "gh001_collector_output.jsonl")
    write(
        scenario(PADDING + gh001, "gh001lexical", sha_salt="lexical-"),
        "gh001_lexical_fallback.jsonl",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
