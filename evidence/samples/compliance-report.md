# PHI Guard — HIPAA Technical Safeguards Evidence Report

> **SAMPLE rendered from tests/fixtures (hand-written tool output), not a real scan. Run 'make report'.**

| | |
|---|---|
| Framework | HIPAA Security Rule - 45 CFR §164.312 Technical Safeguards |
| Commit | `uncommitted` |
| Generated (UTC) | 2026-11-12T16:25:33+00:00 |
| Controls evaluated | 24 / 34 |
| Results | 37 pass · 0 fail · 10 waived |
| Unwaived failures | HIGH 0 · MEDIUM 0 · LOW 0 |
| Waivers applied | yes |

**Tools:** `conftest_tf` ran (loaded tests/fixtures/conftest_tf.json) · `conftest_k8s` ran (loaded tests/fixtures/conftest_k8s.json) · `checkov` ran (loaded tests/fixtures/checkov.json)
> Automated evidence for an academic project using synthetic data. Not a certified
> compliance assessment; mapping checks to HIPAA implementation specifications is an interpretation.

## Control status

| Control | Citation | Severity | Status | Title |
|---|---|---|---|---|
| PHI-AC-01 | 45 CFR §164.312(a)(1) | HIGH | WAIVED | S3 buckets block all public access |
| PHI-AC-02 | 45 CFR §164.312(a)(1) | HIGH | NOT_EVALUATED | RDS instances are not publicly accessible |
| PHI-AC-03 | 45 CFR §164.312(a)(1) | HIGH | NOT_EVALUATED | IAM policies do not grant wildcard admin ("*" on "*") |
| PHI-AC-04 | 45 CFR §164.312(a)(1) | HIGH | NOT_EVALUATED | Security groups do not expose database ports to 0.0.0.0/0 |
| PHI-AC-05 | 45 CFR §164.312(a)(1) | HIGH | NOT_EVALUATED | S3 bucket ACLs are not public |
| PHI-AC-06 | 45 CFR §164.312(a)(1) | MEDIUM | NOT_EVALUATED | Subnets do not auto-assign public IPs |
| PHI-ENC-01 | 45 CFR §164.312(a)(2)(iv) | HIGH | WAIVED | PHI and audit S3 buckets use SSE-KMS with a customer-managed key |
| PHI-ENC-02 | 45 CFR §164.312(a)(2)(iv) | HIGH | WAIVED | RDS storage is encrypted at rest |
| PHI-ENC-03 | 45 CFR §164.312(a)(2)(iv) | MEDIUM | WAIVED | KMS customer-managed keys have rotation enabled |
| PHI-ENC-04 | 45 CFR §164.312(a)(2)(iv) | MEDIUM | NOT_EVALUATED | CloudTrail logs are encrypted with a KMS CMK |
| PHI-AU-01 | 45 CFR §164.312(b) | HIGH | NOT_EVALUATED | CloudTrail is enabled in all regions |
| PHI-AU-02 | 45 CFR §164.312(b) | MEDIUM | PASS | PHI buckets have server access logging enabled |
| PHI-AU-03 | 45 CFR §164.312(b) | MEDIUM | NOT_EVALUATED | VPCs have flow logs enabled |
| PHI-AU-04 | 45 CFR §164.312(b) | MEDIUM | PASS | RDS instances export database logs to CloudWatch |
| PHI-INT-01 | 45 CFR §164.312(c)(1) | HIGH | NOT_EVALUATED | CloudTrail log file validation is enabled |
| PHI-INT-02 | 45 CFR §164.312(c)(1) | MEDIUM | PASS | PHI buckets have versioning enabled |
| PHI-INT-03 | 45 CFR §164.312(c)(1) | MEDIUM | WAIVED | RDS instances have deletion protection |
| PHI-INT-04 | 45 CFR §164.312(c)(1) | MEDIUM | WAIVED | RDS backups are retained for at least 7 days |
| PHI-AUTH-01 | 45 CFR §164.312(d) | MEDIUM | NOT_EVALUATED | RDS instances use IAM database authentication |
| PHI-AUTH-02 | 45 CFR §164.312(d) | MEDIUM | NOT_EVALUATED | IAM account password policy enforces length and complexity |
| PHI-TX-01 | 45 CFR §164.312(e)(1) | HIGH | PASS | PHI and audit buckets deny non-TLS requests |
| PHI-TX-02 | 45 CFR §164.312(e)(2)(ii) | HIGH | PASS | RDS parameter group forces TLS (rds.force_ssl = 1) |
| PHI-TX-03 | 45 CFR §164.312(e)(2)(ii) | HIGH | NOT_EVALUATED | Load balancer listeners use HTTPS with a TLS 1.2+ policy (HTTP only for redirects) |
| PHI-K8S-01 | 45 CFR §164.312(a)(1) | HIGH | WAIVED | Containers are not privileged |
| PHI-K8S-02 | 45 CFR §164.312(a)(1) | HIGH | WAIVED | Containers run as non-root |
| PHI-K8S-03 | 45 CFR §164.312(c)(1) | MEDIUM | PASS | Containers use a read-only root filesystem |
| PHI-K8S-04 | 45 CFR §164.312(a)(1) | LOW | NOT_EVALUATED | Containers set CPU and memory limits |
| PHI-K8S-05 | 45 CFR §164.312(c)(1) | MEDIUM | NOT_EVALUATED | Images use a pinned tag, never "latest" |
| PHI-K8S-06 | 45 CFR §164.312(a)(1) | HIGH | WAIVED | No hard-coded secrets in container environment variables |
| PHI-K8S-07 | 45 CFR §164.312(e)(1) | HIGH | PASS | PHI namespaces have a default-deny NetworkPolicy |
| PHI-K8S-08 | 45 CFR §164.312(e)(2)(ii) | HIGH | WAIVED | Ingresses terminate TLS |
| PHI-K8S-09 | 45 CFR §164.312(b) | MEDIUM | NOT_EVALUATED | Workloads carry data-classification and audit logging labels |
| PHI-K8S-10 | 45 CFR §164.312(a)(1) | HIGH | NOT_EVALUATED | Containers disallow privilege escalation |
| PHI-K8S-11 | 45 CFR §164.312(d) | MEDIUM | PASS | Pods do not auto-mount service account tokens |

## 45 CFR §164.312(a)(1) — Access control

0 fail · 4 waived · 11 pass

| Status | Control | Sev | Resource | Location | Engine / check | Detail |
|---|---|---|---|---|---|---|
| WAIVED | PHI-AC-01 | HIGH | `aws_s3_bucket.legacy_exports` | infra/terraform/aws/s3.tf:166 | conftest / PHI-AC-01 | no aws_s3_bucket_public_access_block with all four flags set to true — *waived: Intentional non-compliant Terraform fixture used to demonstrate detection. (expires 2027-06-30)* |
| WAIVED | PHI-K8S-01 | HIGH | `Deployment/phi-reporting/report-exporter` | /legacy/reporting-stack.yaml:11 | checkov / CKV_K8S_16 | Container should not be privileged — *waived: infra/k8s/legacy is a scan-only fixture and is never deployed. (expires 2027-06-30)* |
| WAIVED | PHI-K8S-02 | HIGH | `Deployment/phi-reporting/report-exporter` | infra/k8s/legacy/reporting-stack.yaml:12 | conftest / PHI-K8S-02 | container "exporter" does not enforce runAsNonRoot — *waived: infra/k8s/legacy is a scan-only fixture and is never deployed. (expires 2027-06-30)* |
| WAIVED | PHI-K8S-06 | HIGH | `Deployment/phi-reporting/report-exporter` | infra/k8s/legacy/reporting-stack.yaml:12 | conftest / PHI-K8S-06 | container "exporter" sets DB_PASSWORD to a literal value; mount a Secret as a file instead — *waived: infra/k8s/legacy is a scan-only fixture and is never deployed. (expires 2027-06-30)* |
| PASS | PHI-AC-01 | HIGH | `aws_s3_bucket.access_logs` | infra/terraform/aws/s3.tf:64 | conftest / PHI-AC-01 | no violation |
| PASS | PHI-AC-01 | HIGH | `aws_s3_bucket.phi_records` | infra/terraform/aws/s3.tf:4 | conftest / PHI-AC-01 | no violation |
| PASS | PHI-K8S-01 | HIGH | `Deployment/phi/patient-api` | /rendered/sample-ehr.yaml:60 | checkov / CKV_K8S_16 | Container should not be privileged |
| PASS | PHI-K8S-02 | HIGH | `CronJob/phi-reporting/nightly-extract` | infra/k8s/legacy/reporting-stack.yaml:44 | conftest / PHI-K8S-02 | no violation |
| PASS | PHI-K8S-02 | HIGH | `Deployment/phi/claims-api` | infra/k8s/rendered/sample-ehr.yaml:163 | conftest / PHI-K8S-02 | no violation |
| PASS | PHI-K8S-02 | HIGH | `Deployment/phi/eligibility-api` | infra/k8s/rendered/sample-ehr.yaml:258 | conftest / PHI-K8S-02 | no violation |
| PASS | PHI-K8S-02 | HIGH | `Deployment/phi/patient-api` | infra/k8s/rendered/sample-ehr.yaml:68 | conftest / PHI-K8S-02 | no violation |
| PASS | PHI-K8S-06 | HIGH | `CronJob/phi-reporting/nightly-extract` | infra/k8s/legacy/reporting-stack.yaml:44 | conftest / PHI-K8S-06 | no violation |
| PASS | PHI-K8S-06 | HIGH | `Deployment/phi/claims-api` | infra/k8s/rendered/sample-ehr.yaml:163 | conftest / PHI-K8S-06 | no violation |
| PASS | PHI-K8S-06 | HIGH | `Deployment/phi/eligibility-api` | infra/k8s/rendered/sample-ehr.yaml:258 | conftest / PHI-K8S-06 | no violation |
| PASS | PHI-K8S-06 | HIGH | `Deployment/phi/patient-api` | infra/k8s/rendered/sample-ehr.yaml:68 | conftest / PHI-K8S-06 | no violation |

## 45 CFR §164.312(a)(2)(iv) — Encryption and decryption (addressable)

0 fail · 3 waived · 2 pass

| Status | Control | Sev | Resource | Location | Engine / check | Detail |
|---|---|---|---|---|---|---|
| WAIVED | PHI-ENC-01 | HIGH | `aws_s3_bucket.legacy_exports` | infra/terraform/aws/s3.tf:166 | conftest / PHI-ENC-01 | bucket is not encrypted with SSE-KMS (aws:kms) using a customer-managed key — *waived: Intentional non-compliant Terraform fixture used to demonstrate detection. (expires 2027-06-30)* |
| WAIVED | PHI-ENC-02 | HIGH | `aws_db_instance.legacy_reporting` | /rds.tf:63 | checkov / CKV_AWS_16 | Ensure all data stored in the RDS is securely encrypted at rest — *waived: Intentional non-compliant Terraform fixture used to demonstrate detection. (expires 2027-06-30)* |
| WAIVED | PHI-ENC-03 | MEDIUM | `aws_kms_key.legacy` | /kms.tf:16 | checkov / CKV_AWS_7 | Ensure rotation for customer created CMKs is enabled — *waived: Intentional non-compliant Terraform fixture used to demonstrate detection. (expires 2027-06-30)* |
| PASS | PHI-ENC-01 | HIGH | `aws_s3_bucket.phi_records` | infra/terraform/aws/s3.tf:4 | conftest / PHI-ENC-01 | no violation |
| PASS | PHI-ENC-02 | HIGH | `aws_db_instance.phi_primary` | /rds.tf:24 | checkov / CKV_AWS_16 | Ensure all data stored in the RDS is securely encrypted at rest |

## 45 CFR §164.312(b) — Audit controls

0 fail · 0 waived · 4 pass

| Status | Control | Sev | Resource | Location | Engine / check | Detail |
|---|---|---|---|---|---|---|
| PASS | PHI-AU-02 | MEDIUM | `aws_s3_bucket.legacy_exports` | infra/terraform/aws/s3.tf:166 | conftest / PHI-AU-02 | no violation |
| PASS | PHI-AU-02 | MEDIUM | `aws_s3_bucket.phi_records` | infra/terraform/aws/s3.tf:4 | conftest / PHI-AU-02 | no violation |
| PASS | PHI-AU-04 | MEDIUM | `aws_db_instance.legacy_reporting` | infra/terraform/aws/rds.tf:61 | conftest / PHI-AU-04 | no violation |
| PASS | PHI-AU-04 | MEDIUM | `aws_db_instance.phi_primary` | infra/terraform/aws/rds.tf:24 | conftest / PHI-AU-04 | no violation |

## 45 CFR §164.312(c)(1) — Integrity

0 fail · 2 waived · 8 pass

| Status | Control | Sev | Resource | Location | Engine / check | Detail |
|---|---|---|---|---|---|---|
| WAIVED | PHI-INT-03 | MEDIUM | `aws_db_instance.legacy_reporting` | /rds.tf:63 | checkov / CKV_PHI_AWS_1 | PHI Guard: RDS instance holding PHI has deletion protection enabled — *waived: Intentional non-compliant Terraform fixture used to demonstrate detection. (expires 2027-06-30)* |
| WAIVED | PHI-INT-04 | MEDIUM | `aws_db_instance.legacy_reporting` | infra/terraform/aws/rds.tf:61 | conftest / PHI-INT-04 | backup_retention_period is 1 days (minimum 7) — *waived: Intentional non-compliant Terraform fixture used to demonstrate detection. (expires 2027-06-30)* |
| PASS | PHI-INT-02 | MEDIUM | `aws_s3_bucket.legacy_exports` | infra/terraform/aws/s3.tf:166 | conftest / PHI-INT-02 | no violation |
| PASS | PHI-INT-02 | MEDIUM | `aws_s3_bucket.phi_records` | infra/terraform/aws/s3.tf:4 | conftest / PHI-INT-02 | no violation |
| PASS | PHI-INT-04 | MEDIUM | `aws_db_instance.phi_primary` | infra/terraform/aws/rds.tf:24 | conftest / PHI-INT-04 | no violation |
| PASS | PHI-K8S-03 | MEDIUM | `CronJob/phi-reporting/nightly-extract` | infra/k8s/legacy/reporting-stack.yaml:44 | conftest / PHI-K8S-03 | no violation |
| PASS | PHI-K8S-03 | MEDIUM | `Deployment/phi-reporting/report-exporter` | infra/k8s/legacy/reporting-stack.yaml:12 | conftest / PHI-K8S-03 | no violation |
| PASS | PHI-K8S-03 | MEDIUM | `Deployment/phi/claims-api` | infra/k8s/rendered/sample-ehr.yaml:163 | conftest / PHI-K8S-03 | no violation |
| PASS | PHI-K8S-03 | MEDIUM | `Deployment/phi/eligibility-api` | infra/k8s/rendered/sample-ehr.yaml:258 | conftest / PHI-K8S-03 | no violation |
| PASS | PHI-K8S-03 | MEDIUM | `Deployment/phi/patient-api` | infra/k8s/rendered/sample-ehr.yaml:68 | conftest / PHI-K8S-03 | no violation |

## 45 CFR §164.312(d) — Person or entity authentication

0 fail · 0 waived · 5 pass

| Status | Control | Sev | Resource | Location | Engine / check | Detail |
|---|---|---|---|---|---|---|
| PASS | PHI-K8S-11 | MEDIUM | `CronJob/phi-reporting/nightly-extract` | infra/k8s/legacy/reporting-stack.yaml:44 | conftest / PHI-K8S-11 | no violation |
| PASS | PHI-K8S-11 | MEDIUM | `Deployment/phi-reporting/report-exporter` | infra/k8s/legacy/reporting-stack.yaml:12 | conftest / PHI-K8S-11 | no violation |
| PASS | PHI-K8S-11 | MEDIUM | `Deployment/phi/claims-api` | infra/k8s/rendered/sample-ehr.yaml:163 | conftest / PHI-K8S-11 | no violation |
| PASS | PHI-K8S-11 | MEDIUM | `Deployment/phi/eligibility-api` | infra/k8s/rendered/sample-ehr.yaml:258 | conftest / PHI-K8S-11 | no violation |
| PASS | PHI-K8S-11 | MEDIUM | `Deployment/phi/patient-api` | infra/k8s/rendered/sample-ehr.yaml:68 | conftest / PHI-K8S-11 | no violation |

## 45 CFR §164.312(e)(1) — Transmission security

0 fail · 0 waived · 4 pass

| Status | Control | Sev | Resource | Location | Engine / check | Detail |
|---|---|---|---|---|---|---|
| PASS | PHI-K8S-07 | HIGH | `Namespace/phi` | infra/k8s/namespaces.yaml:4 | conftest / PHI-K8S-07 | no violation |
| PASS | PHI-K8S-07 | HIGH | `Namespace/phi-reporting` | infra/k8s/legacy/reporting-stack.yaml:5 | conftest / PHI-K8S-07 | no violation |
| PASS | PHI-TX-01 | HIGH | `aws_s3_bucket.legacy_exports` | infra/terraform/aws/s3.tf:166 | conftest / PHI-TX-01 | no violation |
| PASS | PHI-TX-01 | HIGH | `aws_s3_bucket.phi_records` | infra/terraform/aws/s3.tf:4 | conftest / PHI-TX-01 | no violation |

## 45 CFR §164.312(e)(2)(ii) — Encryption (transmission, addressable)

0 fail · 1 waived · 3 pass

| Status | Control | Sev | Resource | Location | Engine / check | Detail |
|---|---|---|---|---|---|---|
| WAIVED | PHI-K8S-08 | HIGH | `Ingress/phi-reporting/legacy-reports` | infra/k8s/legacy/reporting-stack.yaml:78 | conftest / PHI-K8S-08 | Ingress has no spec.tls; traffic is served over plain HTTP — *waived: infra/k8s/legacy is a scan-only fixture and is never deployed. (expires 2027-06-30)* |
| PASS | PHI-K8S-08 | HIGH | `Ingress/phi/sample-ehr` | infra/k8s/rendered/sample-ehr.yaml:353 | conftest / PHI-K8S-08 | no violation |
| PASS | PHI-TX-02 | HIGH | `aws_db_instance.legacy_reporting` | infra/terraform/aws/rds.tf:61 | conftest / PHI-TX-02 | no violation |
| PASS | PHI-TX-02 | HIGH | `aws_db_instance.phi_primary` | infra/terraform/aws/rds.tf:24 | conftest / PHI-TX-02 | no violation |

