"""CKV_PHI_K8S_1 -> PHI-K8S-09, 45 CFR §164.312(b) Audit controls.

Every workload must declare a data-classification label on its pod template.
Workloads classified as PHI must also opt in to audit log collection with
audit.phi-guard.io/log=enabled, which the Fluent Bit / Falco pipeline keys off.
"""
from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.kubernetes.checks.resource.base_spec_check import BaseK8Check

WORKLOADS = ["Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob", "Pod"]


def _pod_labels(conf: dict) -> dict:
    kind = conf.get("kind")
    if kind == "Pod":
        meta = conf.get("metadata") or {}
    elif kind == "CronJob":
        meta = (((conf.get("spec") or {}).get("jobTemplate") or {}).get("spec") or {}).get("template", {}).get("metadata") or {}
    else:
        meta = ((conf.get("spec") or {}).get("template") or {}).get("metadata") or {}
    return meta.get("labels") or {}


class PhiAuditLabels(BaseK8Check):
    def __init__(self) -> None:
        super().__init__(
            name="PHI Guard: workloads carry data-classification and audit logging labels",
            id="CKV_PHI_K8S_1",
            categories=[CheckCategories.LOGGING],
            supported_entities=WORKLOADS,
        )

    def scan_spec_conf(self, conf: dict) -> CheckResult:
        labels = _pod_labels(conf)
        classification = labels.get("data-classification")
        if not classification:
            return CheckResult.FAILED
        if classification == "phi" and labels.get("audit.phi-guard.io/log") != "enabled":
            return CheckResult.FAILED
        return CheckResult.PASSED


check = PhiAuditLabels()
