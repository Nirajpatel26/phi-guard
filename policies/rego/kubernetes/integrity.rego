# 45 CFR §164.312(c)(1) Integrity (Kubernetes)
package hipaa.k8s.integrity

import data.hipaa.k8s.lib
import rego.v1

# ---------------------------------------------------------------- PHI-K8S-03
deny contains msg if {
	some d in lib.workloads
	some c in lib.containers(d.obj)
	not c.securityContext.readOnlyRootFilesystem == true
	msg := lib.msg("PHI-K8S-03", d, sprintf("container %q does not set readOnlyRootFilesystem: true", [c.name]))
}
