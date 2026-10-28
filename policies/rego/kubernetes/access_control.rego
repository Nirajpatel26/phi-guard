# 45 CFR §164.312(a)(1) Access control (Kubernetes)
package hipaa.k8s.access_control

import data.hipaa.k8s.lib
import rego.v1

# ---------------------------------------------------------------- PHI-K8S-02
pod_non_root(obj) if lib.pod_spec(obj).securityContext.runAsNonRoot == true

runs_as_non_root(obj, c) if c.securityContext.runAsNonRoot == true

runs_as_non_root(obj, c) if {
	pod_non_root(obj)
	not c.securityContext.runAsNonRoot == false
	not c.securityContext.runAsUser == 0
}

deny contains msg if {
	some d in lib.workloads
	some c in lib.containers(d.obj)
	not runs_as_non_root(d.obj, c)
	msg := lib.msg("PHI-K8S-02", d, sprintf("container %q does not enforce runAsNonRoot", [c.name]))
}

# ---------------------------------------------------------------- PHI-K8S-06
secret_name_pattern := `(?i)(password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key|credential)`

deny contains msg if {
	some d in lib.workloads
	some c in lib.containers(d.obj)
	some e in object.get(c, "env", [])
	regex.match(secret_name_pattern, e.name)
	is_string(e.value)
	e.value != ""
	msg := lib.msg("PHI-K8S-06", d, sprintf("container %q sets %s to a literal value; mount a Secret as a file instead", [c.name, e.name]))
}
