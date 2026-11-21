"""ExtorQ AI enrichment (advisory only; see docs/ai-integrations.md).

* :mod:`extorq.ai.jev`     - TypeSafe Jev triage: typed questions, deterministic post-processing
* :mod:`extorq.ai.gemini`  - Gemini investigation summaries with evidence-id verification
* :mod:`extorq.ai.service` - :class:`AIService` for the analyst API (cache, cooldown, daily caps)
* :mod:`extorq.ai.worker`  - compose ``ai-worker`` service (Jev triage of new contexts)
* :mod:`extorq.ai.store`   - ``ai_assessments`` persistence
* :mod:`extorq.ai.evaluation` - labelled evaluation of Jev vs a deterministic baseline

AI output never modifies alerts, severity or analyst state, and the platform
works with both providers disabled. Submodules are imported lazily so the
package import has no side effects.
"""
