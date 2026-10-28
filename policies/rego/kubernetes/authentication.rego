# 45 CFR §164.312(d) Person or entity authentication (Kubernetes)
package hipaa.k8s.authentication

import data.hipaa.k8s.lib
import rego.v1

# ---------------------------------------------------------------- PHI-K8S-11
deny contains msg if {
	some d in lib.workloads
	not lib.pod_spec(d.obj).automountServiceAccountToken == false
	msg := lib.msg("PHI-K8S-11", d, "pod spec does not set automountServiceAccountToken: false")
}
