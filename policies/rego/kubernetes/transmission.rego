# 45 CFR §164.312(e)(1) Transmission security and (e)(2)(ii) Encryption (Kubernetes)
package hipaa.k8s.transmission

import data.hipaa.k8s.lib
import rego.v1

# ---------------------------------------------------------------- PHI-K8S-07
phi_namespaces contains d if {
	some d in lib.docs
	d.obj.kind == "Namespace"
	d.obj.metadata.labels["data-classification"] == "phi"
}

default_deny_in(ns) if {
	some d in lib.docs
	d.obj.kind == "NetworkPolicy"
	lib.namespace(d.obj) == ns
	d.obj.spec.podSelector == {}
}

deny contains msg if {
	some d in phi_namespaces
	not default_deny_in(d.obj.metadata.name)
	msg := lib.msg("PHI-K8S-07", d, "PHI namespace has no default-deny NetworkPolicy (podSelector: {})")
}

# ---------------------------------------------------------------- PHI-K8S-08
deny contains msg if {
	some d in lib.docs
	d.obj.kind == "Ingress"
	count(object.get(d.obj, ["spec", "tls"], [])) == 0
	msg := lib.msg("PHI-K8S-08", d, "Ingress has no spec.tls; traffic is served over plain HTTP")
}
