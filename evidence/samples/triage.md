# PHI Guard — triage

## PHI-AC-01 · aws_s3_bucket.legacy_exports (HIGH, WAIVED)

**Citation:** 45 CFR §164.312(a)(1)  
**Location:** infra/terraform/aws/s3.tf:166  
**Source:** mock (mock-template-v1), confidence medium

aws_s3_bucket.legacy_exports fails PHI-AC-01 (S3 buckets block all public access). A bucket without a full public access block can be exposed by a single ACL or policy change, making every stored record readable from the internet. This maps to 45 CFR §164.312(a)(1) (Access control). Detected by conftest check PHI-AC-01: no aws_s3_bucket_public_access_block with all four flags set to true.

```diff
--- a/infra/terraform/aws/s3.tf
+++ b/infra/terraform/aws/s3.tf
@@ aws_s3_bucket.legacy_exports (line 166) @@
+resource "aws_s3_bucket_public_access_block" "legacy_exports" {
+  bucket                  = aws_s3_bucket.legacy_exports.id
+  block_public_acls       = true
+  block_public_policy     = true
+  ignore_public_acls      = true
+  restrict_public_buckets = true
+}
```

## PHI-ENC-01 · aws_s3_bucket.legacy_exports (HIGH, WAIVED)

**Citation:** 45 CFR §164.312(a)(2)(iv)  
**Location:** infra/terraform/aws/s3.tf:166  
**Source:** mock (mock-template-v1), confidence medium

aws_s3_bucket.legacy_exports fails PHI-ENC-01 (PHI and audit S3 buckets use SSE-KMS with a customer-managed key). Without SSE-KMS, decryption is not separately access-controlled or auditable through KMS key policy and CloudTrail. This maps to 45 CFR §164.312(a)(2)(iv) (Encryption and decryption (addressable)). Detected by conftest check PHI-ENC-01: bucket is not encrypted with SSE-KMS (aws:kms) using a customer-managed key.

```diff
--- a/infra/terraform/aws/s3.tf
+++ b/infra/terraform/aws/s3.tf
@@ aws_s3_bucket.legacy_exports (line 166) @@
+resource "aws_s3_bucket_server_side_encryption_configuration" "legacy_exports" {
+  bucket = aws_s3_bucket.legacy_exports.id
+  rule {
+    apply_server_side_encryption_by_default {
+      sse_algorithm     = "aws:kms"
+      kms_master_key_id = aws_kms_key.phi.arn
+    }
+  }
+}
```

## PHI-ENC-02 · aws_db_instance.legacy_reporting (HIGH, WAIVED)

**Citation:** 45 CFR §164.312(a)(2)(iv)  
**Location:** /rds.tf:63  
**Source:** mock (mock-template-v1), confidence medium

aws_db_instance.legacy_reporting fails PHI-ENC-02 (RDS storage is encrypted at rest). Unencrypted database storage and snapshots expose PHI if volumes or snapshots are copied or shared. This maps to 45 CFR §164.312(a)(2)(iv) (Encryption and decryption (addressable)). Detected by checkov check CKV_AWS_16: Ensure all data stored in the RDS is securely encrypted at rest.

```diff
--- a//rds.tf
+++ b//rds.tf
@@ aws_db_instance.legacy_reporting (line 63) @@
+storage_encrypted = true
+kms_key_id        = aws_kms_key.phi.arn
```

## PHI-K8S-01 · Deployment/phi-reporting/report-exporter (HIGH, WAIVED)

**Citation:** 45 CFR §164.312(a)(1)  
**Location:** /legacy/reporting-stack.yaml:11  
**Source:** mock (mock-template-v1), confidence medium

Deployment/phi-reporting/report-exporter fails PHI-K8S-01 (Containers are not privileged). A privileged container has full access to the node and every other workload's data, including PHI volumes. This maps to 45 CFR §164.312(a)(1) (Access control). Detected by checkov check CKV_K8S_16: Container should not be privileged.

```diff
--- a//legacy/reporting-stack.yaml
+++ b//legacy/reporting-stack.yaml
@@ Deployment/phi-reporting/report-exporter (line 11) @@
+securityContext:
+  privileged: false
```

## PHI-K8S-02 · Deployment/phi-reporting/report-exporter (HIGH, WAIVED)

**Citation:** 45 CFR §164.312(a)(1)  
**Location:** infra/k8s/legacy/reporting-stack.yaml:12  
**Source:** mock (mock-template-v1), confidence medium

Deployment/phi-reporting/report-exporter fails PHI-K8S-02 (Containers run as non-root). Root inside a container makes container escape and lateral movement to PHI workloads far easier. This maps to 45 CFR §164.312(a)(1) (Access control). Detected by conftest check PHI-K8S-02: container "exporter" does not enforce runAsNonRoot.

```diff
--- a/infra/k8s/legacy/reporting-stack.yaml
+++ b/infra/k8s/legacy/reporting-stack.yaml
@@ Deployment/phi-reporting/report-exporter (line 12) @@
+securityContext:
+  runAsNonRoot: true
+  runAsUser: 10001
```

## PHI-K8S-06 · Deployment/phi-reporting/report-exporter (HIGH, WAIVED)

**Citation:** 45 CFR §164.312(a)(1)  
**Location:** infra/k8s/legacy/reporting-stack.yaml:12  
**Source:** mock (mock-template-v1), confidence medium

Deployment/phi-reporting/report-exporter fails PHI-K8S-06 (No hard-coded secrets in container environment variables). Literal credentials in manifests leak through git history, kubectl describe and CI logs, granting database access to PHI. This maps to 45 CFR §164.312(a)(1) (Access control). Detected by conftest check PHI-K8S-06: container "exporter" sets DB_PASSWORD to a literal value; mount a Secret as a file instead.

```diff
--- a/infra/k8s/legacy/reporting-stack.yaml
+++ b/infra/k8s/legacy/reporting-stack.yaml
@@ Deployment/phi-reporting/report-exporter (line 12) @@
+volumeMounts:
+  - name: db-credentials
+    mountPath: /etc/phi-secrets
+    readOnly: true
+# volumes: - name: db-credentials / secret: { secretName: phi-db-credentials }
```

## PHI-K8S-08 · Ingress/phi-reporting/legacy-reports (HIGH, WAIVED)

**Citation:** 45 CFR §164.312(e)(2)(ii)  
**Location:** infra/k8s/legacy/reporting-stack.yaml:78  
**Source:** mock (mock-template-v1), confidence medium

Ingress/phi-reporting/legacy-reports fails PHI-K8S-08 (Ingresses terminate TLS). An Ingress without TLS serves PHI over plain HTTP between the client and the cluster edge. This maps to 45 CFR §164.312(e)(2)(ii) (Encryption (transmission, addressable)). Detected by conftest check PHI-K8S-08: Ingress has no spec.tls; traffic is served over plain HTTP.

```diff
--- a/infra/k8s/legacy/reporting-stack.yaml
+++ b/infra/k8s/legacy/reporting-stack.yaml
@@ Ingress/phi-reporting/legacy-reports (line 78) @@
+spec:
+  tls:
+    - hosts: ["<host>"]
+      secretName: <host>-tls
```

## PHI-ENC-03 · aws_kms_key.legacy (MEDIUM, WAIVED)

**Citation:** 45 CFR §164.312(a)(2)(iv)  
**Location:** /kms.tf:16  
**Source:** mock (mock-template-v1), confidence medium

aws_kms_key.legacy fails PHI-ENC-03 (KMS customer-managed keys have rotation enabled). Keys that never rotate increase the impact window of a key compromise. This maps to 45 CFR §164.312(a)(2)(iv) (Encryption and decryption (addressable)). Detected by checkov check CKV_AWS_7: Ensure rotation for customer created CMKs is enabled.

```diff
--- a//kms.tf
+++ b//kms.tf
@@ aws_kms_key.legacy (line 16) @@
+enable_key_rotation = true
```

## PHI-INT-03 · aws_db_instance.legacy_reporting (MEDIUM, WAIVED)

**Citation:** 45 CFR §164.312(c)(1)  
**Location:** /rds.tf:63  
**Source:** mock (mock-template-v1), confidence medium

aws_db_instance.legacy_reporting fails PHI-INT-03 (RDS instances have deletion protection). A database holding PHI can be destroyed by a single API call or a mistaken terraform apply. This maps to 45 CFR §164.312(c)(1) (Integrity). Detected by checkov check CKV_PHI_AWS_1: PHI Guard: RDS instance holding PHI has deletion protection enabled.

```diff
--- a//rds.tf
+++ b//rds.tf
@@ aws_db_instance.legacy_reporting (line 63) @@
+deletion_protection = true
```

## PHI-INT-04 · aws_db_instance.legacy_reporting (MEDIUM, WAIVED)

**Citation:** 45 CFR §164.312(c)(1)  
**Location:** infra/terraform/aws/rds.tf:61  
**Source:** mock (mock-template-v1), confidence medium

aws_db_instance.legacy_reporting fails PHI-INT-04 (RDS backups are retained for at least 7 days). Short retention limits the ability to restore PHI to a known-good state after corruption or ransomware. This maps to 45 CFR §164.312(c)(1) (Integrity). Detected by conftest check PHI-INT-04: backup_retention_period is 1 days (minimum 7).

```diff
--- a/infra/terraform/aws/rds.tf
+++ b/infra/terraform/aws/rds.tf
@@ aws_db_instance.legacy_reporting (line 61) @@
+backup_retention_period = 14
```
