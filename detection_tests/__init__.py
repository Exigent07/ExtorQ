"""ExtorQ detection tests: real activity on the monitored assets, verified end to end.

Every test performs a genuine, reversible action on one monitored asset (the Ubuntu VM
``linux:lab-vm-01``, the kind cluster ``k8s:extorq-lab``, the private GitHub repository
``github:exigent07/extorq-lab`` or the macOS host ``macos:workstation-01``) and then asks the
analyst API whether the expected rule raised an alert for that asset whose ``first_seen`` lies
inside the test's time window. A negative control (a similar but benign action) must NOT
raise the same rule, and every artefact is removed again (try/finally).

There is no "simulation" category and no marker in the telemetry: the collectors, the
gateway and the detector treat these actions exactly like any other activity. Verification
uses only (asset, rule, time window); artefact names start with ``extorq-test-`` so that they
can be found and removed after an interrupted run.

Run from the repository root::

    uv run python -m detection_tests run --asset linux|kubernetes|github|macos|all \
        [--only RULE] [--skip-negatives]
    uv run python -m detection_tests list [--asset ...] [--markdown]
    uv run python -m detection_tests cleanup --asset ...

Documentation (each test, safety properties, expected alert, negative control, cleanup):
``docs/detection-tests.md``.
"""

from __future__ import annotations

#: Version of the runner and of the report format it writes (``report.REPORT_SCHEMA``).
__version__ = "1.0.0"
