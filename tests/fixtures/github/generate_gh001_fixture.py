"""Generate tests/fixtures/github/gh001_collector_output.jsonl (SYNTHETIC fixture).

The GitHub API is the synthetic fake from tests/unit/github/github_fakes.py (owner
``example-org``, logins ``synthetic-*``); the workflow files are the real lab baseline
(lab/github-repo/.github/workflows/ci.yml) and the GH-001 template
(simulations/github/templates/ci-gh001.yml). The events are produced by the real
collector code path (RepoPoller -> workflow analyser -> EventBuilder), so the fixture shows
exactly what the GitHub collector emits for the GH-001 scenario: a baseline commit, the
escalation commit (``[extorq-sim gh001fixture]``) and the cleanup commit. Every event is
labelled ``extorq.fixture=synthetic``.

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

CI = ".github/workflows/ci.yml"
OUT = Path(__file__).with_name("gh001_collector_output.jsonl")


def main() -> int:
    lab = (ROOT / "lab/github-repo" / CI).read_text(encoding="utf-8")
    gh001 = (ROOT / "simulations/github/templates/ci-gh001.yml").read_text(encoding="utf-8")
    fake = FakeGitHub()
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
        "ci: add PR preview job and broaden token permissions [extorq-sim gh001fixture]",
        {CI: gh001},
        pusher="synthetic-operator",
    )
    poll()
    fake.commit(
        "ci: restore least-privilege CI workflow [extorq-sim gh001fixture cleanup]", {CI: lab}
    )
    poll()
    wanted = {"github.commit.observed", "github.workflow.modified"}
    lines = []
    for event in events:
        if event.event_type in wanted:
            labelled = event.model_copy(update={"labels": {"extorq.fixture": "synthetic"}})
            lines.append(json.dumps(labelled.model_dump(mode="json"), sort_keys=True))
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {len(lines)} events to {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
