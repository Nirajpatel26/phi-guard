# 45 CFR §164.312(e)(1) Transmission security and (e)(2)(ii) Encryption in transit
package hipaa.tf.transmission

import data.hipaa.tf.lib
import rego.v1

# ---------------------------------------------------------------- PHI-TX-01
tls_only_policy(bucket_addr) if {
	some p in lib.referencing("aws_s3_bucket_policy", "bucket", bucket_addr)
	doc := json.unmarshal(lib.after(p).policy)
	some s in lib.as_array(doc.Statement)
	s.Effect == "Deny"
	v := s.Condition.Bool["aws:SecureTransport"]
	v in {"false", false}
}

deny contains msg if {
	some b in lib.resources("aws_s3_bucket")
	lib.classification(b) in {"phi", "audit"}
	not tls_only_policy(b.address)
	msg := lib.msg("PHI-TX-01", b.address, "no bucket policy denying requests where aws:SecureTransport is false")
}

# ---------------------------------------------------------------- PHI-TX-02
forces_ssl(pg) if {
	some p in lib.arr(lib.after(pg).parameter)
	p.name == "rds.force_ssl"
	p.value == "1"
}

db_forces_ssl(db) if {
	refs := lib.refs(db.address, "parameter_group_name")
	some pg in lib.resources("aws_db_parameter_group")
	pg.address in refs
	forces_ssl(pg)
}

deny contains msg if {
	some db in lib.resources("aws_db_instance")
	not db_forces_ssl(db)
	msg := lib.msg("PHI-TX-02", db.address, "instance does not use a parameter group with rds.force_ssl = 1")
}

# ---------------------------------------------------------------- PHI-TX-03
approved_tls_policies := {
	"ELBSecurityPolicy-TLS13-1-2-2021-06",
	"ELBSecurityPolicy-TLS13-1-2-Res-2021-06",
	"ELBSecurityPolicy-TLS13-1-3-2021-06",
	"ELBSecurityPolicy-FS-1-2-Res-2020-10",
	"ELBSecurityPolicy-TLS-1-2-Ext-2018-06",
}

listener_types := {"aws_lb_listener", "aws_alb_listener"}

redirects_to_https(a) if {
	some act in lib.arr(a.default_action)
	act.type == "redirect"
	some r in lib.arr(act.redirect)
	r.protocol == "HTTPS"
}

approved_policy(p) if p in approved_tls_policies

deny contains msg if {
	some t in listener_types
	some l in lib.resources(t)
	a := lib.after(l)
	a.protocol == "HTTP"
	not redirects_to_https(a)
	msg := lib.msg("PHI-TX-03", l.address, sprintf("HTTP listener on port %v forwards traffic instead of redirecting to HTTPS", [a.port]))
}

deny contains msg if {
	some t in listener_types
	some l in lib.resources(t)
	a := lib.after(l)
	a.protocol == "HTTPS"
	not approved_policy(object.get(a, "ssl_policy", ""))
	msg := lib.msg("PHI-TX-03", l.address, sprintf("HTTPS listener uses non-approved ssl_policy %q", [object.get(a, "ssl_policy", "")]))
}
