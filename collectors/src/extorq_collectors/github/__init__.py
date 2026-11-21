"""GitHub repository security monitoring for ExtorQ.

Modules: ``client`` (REST client: timeouts, ETags, pagination, rate limits), ``token``
(token resolution), ``workflow`` (offline workflow analyser), ``poller`` (per-repo
collection), ``posture`` / ``alerts`` / ``findings`` (scans), ``collector`` (SDK adapter,
``extorq_collectors.github.collector:GitHubCollector``), ``analyze`` (offline CLI).
"""
