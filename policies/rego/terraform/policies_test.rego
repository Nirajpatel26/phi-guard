# Run with: conftest verify --policy policies/rego/terraform
package hipaa.tf.policies_test

import data.hipaa.tf.access_control
import data.hipaa.tf.integrity
import data.hipaa.tf.transmission
import rego.v1

rc(type, name, after) := {"address": sprintf("%s.%s", [type, name]), "type": type, "name": name,
	"change": {"actions": ["create"], "after": after}}

cfg(type, name, attr, target) := {"address": sprintf("%s.%s", [type, name]), "type": type, "name": name,
	"expressions": {attr: {"references": [sprintf("%s.id", [target]), target]}}}

plan_with_bucket(extra_rcs, extra_cfg) := {
	"resource_changes": array.concat([rc("aws_s3_bucket", "b", {"tags": {"data-classification": "phi"}})], extra_rcs),
	"configuration": {"root_module": {"resources": extra_cfg}},
}

test_bucket_without_pab_denied if {
	msgs := access_control.deny with input as plan_with_bucket([], [])
	some m in msgs
	startswith(m, "[PHI-AC-01] aws_s3_bucket.b")
}

test_bucket_with_full_pab_allowed if {
	pab := rc("aws_s3_bucket_public_access_block", "b", {"block_public_acls": true, "block_public_policy": true,
		"ignore_public_acls": true, "restrict_public_buckets": true})
	inp := plan_with_bucket([pab], [cfg("aws_s3_bucket_public_access_block", "b", "bucket", "aws_s3_bucket.b")])
	msgs := access_control.deny with input as inp
	not any_prefix(msgs, "[PHI-AC-01]")
}

test_wildcard_admin_denied if {
	pol := rc("aws_iam_policy", "admin", {"policy": "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"})
	msgs := access_control.deny with input as {"resource_changes": [pol]}
	some m in msgs
	startswith(m, "[PHI-AC-03]")
}

test_db_open_to_world_denied if {
	sg := rc("aws_security_group", "db", {"ingress": [{"from_port": 5432, "to_port": 5432, "cidr_blocks": ["0.0.0.0/0"]}]})
	msgs := access_control.deny with input as {"resource_changes": [sg]}
	some m in msgs
	startswith(m, "[PHI-AC-04]")
}

test_short_backup_denied if {
	db := rc("aws_db_instance", "x", {"backup_retention_period": 1})
	msgs := integrity.deny with input as {"resource_changes": [db]}
	some m in msgs
	startswith(m, "[PHI-INT-04]")
}

test_http_forward_listener_denied_redirect_allowed if {
	fwd := rc("aws_lb_listener", "fwd", {"protocol": "HTTP", "port": 8080, "default_action": [{"type": "forward"}]})
	red := rc("aws_lb_listener", "red", {"protocol": "HTTP", "port": 80,
		"default_action": [{"type": "redirect", "redirect": [{"protocol": "HTTPS"}]}]})
	msgs := transmission.deny with input as {"resource_changes": [fwd, red]}
	some m in msgs
	startswith(m, "[PHI-TX-03] aws_lb_listener.fwd")
	not any_prefix(msgs, "[PHI-TX-03] aws_lb_listener.red")
}

any_prefix(msgs, p) if {
	some m in msgs
	startswith(m, p)
}
