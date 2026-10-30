# 45 CFR §164.312(b) Audit controls
package hipaa.tf.audit

import data.hipaa.tf.lib
import rego.v1

# ---------------------------------------------------------------- PHI-AU-02
has_access_logging(bucket_addr) if {
	count(lib.referencing("aws_s3_bucket_logging", "bucket", bucket_addr)) > 0
}

deny contains msg if {
	some b in lib.resources("aws_s3_bucket")
	lib.classification(b) == "phi"
	not has_access_logging(b.address)
	msg := lib.msg("PHI-AU-02", b.address, "PHI bucket has no aws_s3_bucket_logging configuration")
}

# ---------------------------------------------------------------- PHI-AU-03
has_flow_log(vpc_addr) if {
	count(lib.referencing("aws_flow_log", "vpc_id", vpc_addr)) > 0
}

deny contains msg if {
	some v in lib.resources("aws_vpc")
	not has_flow_log(v.address)
	msg := lib.msg("PHI-AU-03", v.address, "VPC has no aws_flow_log")
}

# ---------------------------------------------------------------- PHI-AU-04
deny contains msg if {
	some db in lib.resources("aws_db_instance")
	count(lib.arr(object.get(lib.after(db), "enabled_cloudwatch_logs_exports", []))) == 0
	msg := lib.msg("PHI-AU-04", db.address, "enabled_cloudwatch_logs_exports is empty; database logs are not exported")
}
