# Helpers for evaluating `terraform show -json` plan output.
# Assumes a flat root module (no child modules), which is how infra/terraform/aws is laid out.
package hipaa.tf.lib

import rego.v1

planned := [rc |
	some rc in object.get(input, "resource_changes", [])
	not is_delete(rc)
]

is_delete(rc) if rc.change.actions == ["delete"]

resources(t) := [rc | some rc in planned; rc.type == t]

after(rc) := a if {
	a := rc.change.after
	is_object(a)
} else := {}

arr(x) := x if {
	is_array(x)
} else := []

as_array(x) := x if is_array(x)

as_array(x) := [x] if not is_array(x)

config_resources := object.get(input, ["configuration", "root_module", "resources"], [])

# Addresses referenced by attribute `attr` of the configured resource `addr`.
# Plan JSON keeps references (e.g. "aws_s3_bucket.x.id", "aws_s3_bucket.x") even
# when the value itself is unknown until apply.
refs(addr, attr) := [r |
	some c in config_resources
	c.address == addr
	some r in object.get(c, ["expressions", attr, "references"], [])
]

# Planned resources of type t whose attribute attr points at target address.
referencing(t, attr, target) := [rc |
	some rc in resources(t)
	target in refs(rc.address, attr)
]

tags(rc) := t if {
	t := after(rc).tags
	is_object(t)
} else := {}

classification(rc) := object.get(tags(rc), "data-classification", "")

msg(id, addr, text) := sprintf("[%s] %s :: %s", [id, addr, text])
