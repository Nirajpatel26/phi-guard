# 45 CFR §164.312(d) Person or entity authentication
package hipaa.tf.authentication

import data.hipaa.tf.lib
import rego.v1

# ---------------------------------------------------------------- PHI-AUTH-02
min_length := 14

deny contains msg if {
	count(lib.resources("aws_iam_account_password_policy")) == 0
	msg := lib.msg("PHI-AUTH-02", "account", "no aws_iam_account_password_policy is managed in code")
}

deny contains msg if {
	some p in lib.resources("aws_iam_account_password_policy")
	length := object.get(lib.after(p), "minimum_password_length", 0)
	length < min_length
	msg := lib.msg("PHI-AUTH-02", p.address, sprintf("minimum_password_length is %v (minimum %v)", [length, min_length]))
}

complexity_flags := ["require_lowercase_characters", "require_uppercase_characters", "require_numbers", "require_symbols"]

deny contains msg if {
	some p in lib.resources("aws_iam_account_password_policy")
	some k in complexity_flags
	object.get(lib.after(p), k, false) != true
	msg := lib.msg("PHI-AUTH-02", p.address, sprintf("%s is not true", [k]))
}
