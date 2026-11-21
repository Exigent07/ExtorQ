"""Kubernetes inventory, service hierarchy, Events and posture collector (owner: B2).

Entry point for ``extorq-collect run``:
``extorq_collectors.kubernetes.collector:KubernetesInventoryCollector``
(config ``config/collectors/kubernetes.yaml``, producer ``k8s-inventory-extorq-lab``).
Container logs and API audit events do NOT come from here: they are shipped by the
OTel Collector DaemonSet and normalised by ``extorq.ingest.otlp_k8s``.
"""
