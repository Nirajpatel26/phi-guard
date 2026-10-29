# Run with: conftest verify --policy policies/rego/kubernetes
package hipaa.k8s.policies_test

import data.hipaa.k8s.access_control
import data.hipaa.k8s.authentication
import data.hipaa.k8s.integrity
import data.hipaa.k8s.transmission
import rego.v1

good_deploy := {
	"apiVersion": "apps/v1", "kind": "Deployment",
	"metadata": {"name": "api", "namespace": "phi"},
	"spec": {"template": {"metadata": {"labels": {"app": "api"}}, "spec": {
		"automountServiceAccountToken": false,
		"securityContext": {"runAsNonRoot": true},
		"containers": [{"name": "app", "image": "x:1.0", "securityContext": {"readOnlyRootFilesystem": true}}],
	}}},
}

bad_deploy := {
	"apiVersion": "apps/v1", "kind": "Deployment",
	"metadata": {"name": "legacy", "namespace": "phi"},
	"spec": {"template": {"metadata": {"labels": {"app": "legacy"}}, "spec": {"containers": [{
		"name": "app", "image": "x:latest",
		"securityContext": {"runAsUser": 0},
		"env": [{"name": "DB_PASSWORD", "value": "hunter2"}],
	}]}}},
}

phi_ns := {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "phi", "labels": {"data-classification": "phi"}}}

deny_all := {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
	"metadata": {"name": "default-deny", "namespace": "phi"}, "spec": {"podSelector": {}}}

combined(docs) := [{"path": "test.yaml", "contents": docs}]

test_good_workload_passes_all if {
	inp := combined([good_deploy])
	count(access_control.deny) == 0 with input as inp
	count(integrity.deny) == 0 with input as inp
	count(authentication.deny) == 0 with input as inp
}

test_bad_workload_flagged if {
	inp := combined([bad_deploy])
	msgs := access_control.deny with input as inp
	some m1 in msgs
	startswith(m1, "[PHI-K8S-02]")
	some m2 in msgs
	startswith(m2, "[PHI-K8S-06]")
	count(integrity.deny) == 1 with input as inp
	count(authentication.deny) == 1 with input as inp
}

test_phi_namespace_requires_network_policy if {
	count(transmission.deny) == 1 with input as combined([phi_ns])
	count(transmission.deny) == 0 with input as combined([phi_ns, deny_all])
}

test_ingress_without_tls_flagged if {
	ing := {"apiVersion": "networking.k8s.io/v1", "kind": "Ingress",
		"metadata": {"name": "web", "namespace": "phi"}, "spec": {"rules": []}}
	msgs := transmission.deny with input as combined([ing])
	some m in msgs
	startswith(m, "[PHI-K8S-08] Ingress/phi/web")
}
