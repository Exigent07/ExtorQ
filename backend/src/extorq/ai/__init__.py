"""ExtorQ AI enrichment: advisory Jev triage (see docs/ai-integrations.md).

Jev (TypeSafe "System One") is the only AI provider. It answers fixed, typed questions
about one InvestigationContext; ExtorQ turns the probabilities into a triage hint with a
deterministic procedure.

* :mod:`extorq.ai.jev`        - question sets, answer validation, deterministic decision
* :mod:`extorq.ai.projection` - allow-list projection of a context into Jev's state
* :mod:`extorq.ai.sanitize`   - normalisation, redaction and bounding of untrusted text
* :mod:`extorq.ai.worker`     - compose ``ai-worker`` service (triage of new contexts)
* :mod:`extorq.ai.service`    - :class:`AIService` for on-demand triage (``extorq ai triage``)
* :mod:`extorq.ai.store`      - ``ai_assessments`` / ``pipeline_health`` persistence
* :mod:`extorq.ai.budget`     - persisted daily cap with an in-process guard
* :mod:`extorq.ai.evaluation` - labelled evaluation of Jev against a deterministic baseline

AI output never modifies alerts, severity or analyst state, and the platform works
unchanged with Jev disabled (the default). Submodules are imported lazily so importing
the package has no side effects.
"""
