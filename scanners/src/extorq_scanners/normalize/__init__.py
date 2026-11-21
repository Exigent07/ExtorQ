"""Pure normalisers: scanner JSON output -> contract PostureFindings + coverage facts.

Normalisers never perform I/O, never run tools and never decide the final scan
status (see :mod:`extorq_scanners.status`). They raise
:class:`extorq_scanners.models.ReportFormatError` when output is unusable.
"""
