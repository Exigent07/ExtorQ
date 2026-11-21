"""Export the OpenAPI document: ``uv run python -m extorq.api.openapi_export [path]``.

Default output: ``docs/api/openapi.json``. The document is generated from the code
(no network, no storage access) and is the source for the console's TypeScript types.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

DEFAULT_OUTPUT = Path("docs/api/openapi.json")


def build_openapi() -> dict[str, Any]:
    from extorq.api.app import create_app
    from extorq.api.repository import ClickHouseRepository
    from extorq.api.settings import ApiSettings

    # Repository and token are never used during schema generation; the repository is
    # lazy (no connection is opened) and a missing token only logs a warning.
    app = create_app(settings=ApiSettings(), repository=ClickHouseRepository())
    return app.openapi()


def render() -> str:
    return json.dumps(build_openapi(), indent=2, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    output = Path(args[0]) if args else DEFAULT_OUTPUT
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render(), encoding="utf-8")
    print(f"wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
