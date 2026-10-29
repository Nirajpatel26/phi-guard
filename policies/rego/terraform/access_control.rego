# 45 CFR §164.312(a)(1) Access control
package hipaa.tf.access_control

import data.hipaa.tf.lib
import rego.v1

# ---------------------------------------------------------------- PHI-AC-01
pab_complete(bucket_addr) if {
	some p in lib.referencing("aws_s3_bucket_public_access_block", "bucket", bucket_addr)
	a := lib.after(p)
	a.block_public_acls == true
	a.block_public_policy == true
	a.ignore_public_acls == true
	a.restrict_public_buckets == true
}

deny contains msg if {
	some b in lib.resources("aws_s3_bucket")
	not pab_complete(b.address)
	msg := lib.msg("PHI-AC-01", b.address, "no aws_s3_bucket_public_access_block with all four flags set to true")
}

# ---------------------------------------------------------------- PHI-AC-03
iam_policy_types := {"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"}

deny contains msg if {
	some t in iam_policy_types
	some p in lib.resources(t)
	doc := json.unmarshal(lib.after(p).policy)
	some s in lib.as_array(doc.Statement)
	s.Effect == "Allow"
	"*" in lib.as_array(object.get(s, "Action", []))
	"*" in lib.as_array(object.get(s, "Resource", []))
	msg := lib.msg("PHI-AC-03", p.address, "policy allows Action \"*\" on Resource \"*\" (full administrative access)")
}

# ---------------------------------------------------------------- PHI-AC-04
db_ports := {1433, 1521, 3306, 5432, 5439, 6379, 27017}

open_cidr(c) if c in {"0.0.0.0/0", "::/0"}

covers_db_port(from, to) if {
	some p in db_ports
	from <= p
	p <= to
}

# protocol "-1" (all traffic) is expressed as ports 0-0
covers_db_port(from, to) if {
	from == 0
	to == 0
}

deny contains msg if {
	some sg in lib.resources("aws_security_group")
	some ing in lib.arr(object.get(lib.after(sg), "ingress", []))
	cidrs := array.concat(lib.arr(object.get(ing, "cidr_blocks", [])), lib.arr(object.get(ing, "ipv6_cidr_blocks", [])))
	some c in cidrs
	open_cidr(c)
	covers_db_port(ing.from_port, ing.to_port)
	msg := lib.msg("PHI-AC-04", sg.address, sprintf("ingress %v-%v open to %s covers a database port", [ing.from_port, ing.to_port, c]))
}

deny contains msg if {
	some r in lib.resources("aws_security_group_rule")
	a := lib.after(r)
	a.type == "ingress"
	cidrs := array.concat(lib.arr(object.get(a, "cidr_blocks", [])), lib.arr(object.get(a, "ipv6_cidr_blocks", [])))
	some c in cidrs
	open_cidr(c)
	covers_db_port(a.from_port, a.to_port)
	msg := lib.msg("PHI-AC-04", r.address, sprintf("ingress rule open to %s covers a database port", [c]))
}

deny contains msg if {
	some r in lib.resources("aws_vpc_security_group_ingress_rule")
	a := lib.after(r)
	some c in [object.get(a, "cidr_ipv4", ""), object.get(a, "cidr_ipv6", "")]
	open_cidr(c)
	vpc_rule_covers_db(a)
	msg := lib.msg("PHI-AC-04", r.address, sprintf("ingress rule open to %s covers a database port", [c]))
}

vpc_rule_covers_db(a) if a.ip_protocol == "-1"

vpc_rule_covers_db(a) if covers_db_port(a.from_port, a.to_port)

# ---------------------------------------------------------------- PHI-AC-05
public_acls := {"public-read", "public-read-write", "authenticated-read"}

deny contains msg if {
	some r in lib.resources("aws_s3_bucket_acl")
	acl := object.get(lib.after(r), "acl", "")
	acl in public_acls
	msg := lib.msg("PHI-AC-05", r.address, sprintf("bucket ACL is %q", [acl]))
}
