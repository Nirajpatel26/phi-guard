# 45 CFR §164.312(a)(2)(iv) Encryption and decryption
package hipaa.tf.encryption

import data.hipaa.tf.lib
import rego.v1

kms_algorithms := {"aws:kms", "aws:kms:dsse"}

# ---------------------------------------------------------------- PHI-ENC-01
sse_kms(bucket_addr) if {
	some c in lib.referencing("aws_s3_bucket_server_side_encryption_configuration", "bucket", bucket_addr)
	some r in lib.arr(lib.after(c).rule)
	some d in lib.arr(r.apply_server_side_encryption_by_default)
	d.sse_algorithm in kms_algorithms
}

deny contains msg if {
	some b in lib.resources("aws_s3_bucket")
	lib.classification(b) in {"phi", "audit"}
	not sse_kms(b.address)
	msg := lib.msg("PHI-ENC-01", b.address, "bucket is not encrypted with SSE-KMS (aws:kms) using a customer-managed key")
}
