"""ExtorQ analyst API (PLAN section 5.2).

Entry point: :func:`extorq.api.app.create_app` (served by ``extorq api``; the
development runner is ``python -m extorq.api --port 8100``). The package is kept
import-light: FastAPI and the storage layer are imported by ``extorq.api.app``.
"""
