# 45 CFR §164.312(c)(1) Integrity
package hipaa.tf.integrity

import data.hipaa.tf.lib
import rego.v1

# ---------------------------------------------------------------- PHI-INT-02
versioning_enabled(bucket_addr) if {
	some v in lib.referencing("aws_s3_bucket_versioning", "bucket", bucket_addr)
	some cfg in lib.arr(lib.after(v).versioning_configuration)
	cfg.status == "Enabled"
}

deny contains msg if {
	some b in lib.resources("aws_s3_bucket")
	lib.classification(b) == "phi"
	not versioning_enabled(b.address)
	msg := lib.msg("PHI-INT-02", b.address, "PHI bucket does not have versioning enabled")
}

# ---------------------------------------------------------------- PHI-INT-04
min_backup_days := 7

deny contains msg if {
	some db in lib.resources("aws_db_instance")
	days := object.get(lib.after(db), "backup_retention_period", 0)
	days < min_backup_days
	msg := lib.msg("PHI-INT-04", db.address, sprintf("backup_retention_period is %v days (minimum %v)", [days, min_backup_days]))
}
