# HIPAA control mapping

_Generated from `policies/mapping.yaml` by `scripts/gen_control_doc.py`. Edit the YAML, not this file._

Framework: HIPAA Security Rule - 45 CFR §164.312 Technical Safeguards. 34 controls.

Mapping a technical check to a HIPAA implementation specification is an interpretation. Rows marked *indirect* support the safeguard without directly implementing it.

| Citation | Safeguard | Controls |
|---|---|---|
| 45 CFR §164.312(a)(1) | Access control | 11 (PHI-AC-01, PHI-AC-02, PHI-AC-03, PHI-AC-04, PHI-AC-05, PHI-AC-06, PHI-K8S-01, PHI-K8S-02, PHI-K8S-04, PHI-K8S-06, PHI-K8S-10) |
| 45 CFR §164.312(a)(2)(iv) | Encryption and decryption (addressable) | 4 (PHI-ENC-01, PHI-ENC-02, PHI-ENC-03, PHI-ENC-04) |
| 45 CFR §164.312(b) | Audit controls | 5 (PHI-AU-01, PHI-AU-02, PHI-AU-03, PHI-AU-04, PHI-K8S-09) |
| 45 CFR §164.312(c)(1) | Integrity | 6 (PHI-INT-01, PHI-INT-02, PHI-INT-03, PHI-INT-04, PHI-K8S-03, PHI-K8S-05) |
| 45 CFR §164.312(d) | Person or entity authentication | 3 (PHI-AUTH-01, PHI-AUTH-02, PHI-K8S-11) |
| 45 CFR §164.312(e)(1) | Transmission security | 2 (PHI-TX-01, PHI-K8S-07) |
| 45 CFR §164.312(e)(2)(ii) | Encryption (transmission, addressable) | 3 (PHI-TX-02, PHI-TX-03, PHI-K8S-08) |

| Control | Citation | Severity | Scope | Engine | Check ID(s) | Title |
|---|---|---|---|---|---|---|
| PHI-AC-01 | 45 CFR §164.312(a)(1) | HIGH | terraform | rego | `PHI-AC-01` | S3 buckets block all public access |
| PHI-AC-02 | 45 CFR §164.312(a)(1) | HIGH | terraform | checkov | `CKV_AWS_17` | RDS instances are not publicly accessible |
| PHI-AC-03 | 45 CFR §164.312(a)(1) | HIGH | terraform | rego | `PHI-AC-03` | IAM policies do not grant wildcard admin ("*" on "*") |
| PHI-AC-04 | 45 CFR §164.312(a)(1) | HIGH | terraform | rego | `PHI-AC-04` | Security groups do not expose database ports to 0.0.0.0/0 |
| PHI-AC-05 | 45 CFR §164.312(a)(1) | HIGH | terraform | rego | `PHI-AC-05` | S3 bucket ACLs are not public |
| PHI-AC-06 | 45 CFR §164.312(a)(1) | MEDIUM | terraform | checkov | `CKV_AWS_130` | Subnets do not auto-assign public IPs |
| PHI-ENC-01 | 45 CFR §164.312(a)(2)(iv) | HIGH | terraform | rego | `PHI-ENC-01` | PHI and audit S3 buckets use SSE-KMS with a customer-managed key |
| PHI-ENC-02 | 45 CFR §164.312(a)(2)(iv) | HIGH | terraform | checkov | `CKV_AWS_16` | RDS storage is encrypted at rest |
| PHI-ENC-03 | 45 CFR §164.312(a)(2)(iv) | MEDIUM | terraform | checkov | `CKV_AWS_7` | KMS customer-managed keys have rotation enabled |
| PHI-ENC-04 | 45 CFR §164.312(a)(2)(iv) | MEDIUM | terraform | checkov | `CKV_AWS_35` | CloudTrail logs are encrypted with a KMS CMK |
| PHI-AU-01 | 45 CFR §164.312(b) | HIGH | terraform | checkov | `CKV_AWS_67` | CloudTrail is enabled in all regions |
| PHI-AU-02 | 45 CFR §164.312(b) | MEDIUM | terraform | rego | `PHI-AU-02` | PHI buckets have server access logging enabled |
| PHI-AU-03 | 45 CFR §164.312(b) | MEDIUM | terraform | rego | `PHI-AU-03` | VPCs have flow logs enabled |
| PHI-AU-04 | 45 CFR §164.312(b) | MEDIUM | terraform | rego | `PHI-AU-04` | RDS instances export database logs to CloudWatch |
| PHI-INT-01 | 45 CFR §164.312(c)(1) | HIGH | terraform | checkov | `CKV_AWS_36` | CloudTrail log file validation is enabled |
| PHI-INT-02 | 45 CFR §164.312(c)(1) | MEDIUM | terraform | rego | `PHI-INT-02` | PHI buckets have versioning enabled |
| PHI-INT-03 | 45 CFR §164.312(c)(1) | MEDIUM | terraform | checkov | `CKV_PHI_AWS_1` | RDS instances have deletion protection |
| PHI-INT-04 | 45 CFR §164.312(c)(1) | MEDIUM | terraform | rego | `PHI-INT-04` | RDS backups are retained for at least 7 days |
| PHI-AUTH-01 | 45 CFR §164.312(d) | MEDIUM | terraform | checkov | `CKV_PHI_AWS_2` | RDS instances use IAM database authentication |
| PHI-AUTH-02 | 45 CFR §164.312(d) | MEDIUM | terraform | rego | `PHI-AUTH-02` | IAM account password policy enforces length and complexity |
| PHI-TX-01 | 45 CFR §164.312(e)(1) | HIGH | terraform | rego | `PHI-TX-01` | PHI and audit buckets deny non-TLS requests |
| PHI-TX-02 | 45 CFR §164.312(e)(2)(ii) | HIGH | terraform | rego | `PHI-TX-02` | RDS parameter group forces TLS (rds.force_ssl = 1) |
| PHI-TX-03 | 45 CFR §164.312(e)(2)(ii) | HIGH | terraform | rego | `PHI-TX-03` | Load balancer listeners use HTTPS with a TLS 1.2+ policy (HTTP only for redirects) |
| PHI-K8S-01 | 45 CFR §164.312(a)(1) | HIGH | kubernetes | checkov | `CKV_K8S_16` | Containers are not privileged |
| PHI-K8S-02 | 45 CFR §164.312(a)(1) | HIGH | kubernetes | rego | `PHI-K8S-02` | Containers run as non-root |
| PHI-K8S-03 | 45 CFR §164.312(c)(1) | MEDIUM | kubernetes | rego | `PHI-K8S-03` | Containers use a read-only root filesystem |
| PHI-K8S-04 | 45 CFR §164.312(a)(1) | LOW | kubernetes | checkov | `CKV_K8S_11, CKV_K8S_13` | Containers set CPU and memory limits *(indirect)* |
| PHI-K8S-05 | 45 CFR §164.312(c)(1) | MEDIUM | kubernetes | checkov | `CKV_K8S_14` | Images use a pinned tag, never "latest" |
| PHI-K8S-06 | 45 CFR §164.312(a)(1) | HIGH | kubernetes | rego | `PHI-K8S-06` | No hard-coded secrets in container environment variables |
| PHI-K8S-07 | 45 CFR §164.312(e)(1) | HIGH | kubernetes | rego | `PHI-K8S-07` | PHI namespaces have a default-deny NetworkPolicy |
| PHI-K8S-08 | 45 CFR §164.312(e)(2)(ii) | HIGH | kubernetes | rego | `PHI-K8S-08` | Ingresses terminate TLS |
| PHI-K8S-09 | 45 CFR §164.312(b) | MEDIUM | kubernetes | checkov | `CKV_PHI_K8S_1` | Workloads carry data-classification and audit logging labels |
| PHI-K8S-10 | 45 CFR §164.312(a)(1) | HIGH | kubernetes | checkov | `CKV_K8S_20` | Containers disallow privilege escalation |
| PHI-K8S-11 | 45 CFR §164.312(d) | MEDIUM | kubernetes | rego | `PHI-K8S-11` | Pods do not auto-mount service account tokens |

**Engines.** `rego` controls live in `policies/rego/{terraform,kubernetes}/` (one file per safeguard family) and run under Conftest against the Terraform plan JSON and the Kubernetes manifests. `checkov` controls reuse built-in Checkov checks (`CKV_AWS_*`, `CKV_K8S_*`) or custom ones in `policies/checkov/` (`CKV_PHI_*`).
