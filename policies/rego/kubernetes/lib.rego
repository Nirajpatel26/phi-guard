# Helpers for Kubernetes manifests evaluated with `conftest test --combine`.
# In combine mode `input` is a list of {"path": <file>, "contents": <doc or [docs]>},
# which lets cross-document rules (e.g. "namespace has a NetworkPolicy") work.
package hipaa.k8s.lib

import rego.v1

docs contains {"path": f.path, "obj": c} if {
	some f in input
	is_array(f.contents)
	some c in f.contents
	is_object(c)
}

docs contains {"path": f.path, "obj": f.contents} if {
	some f in input
	is_object(f.contents)
}

workload_kinds := {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob", "Pod"}

cluster_scoped := {"Namespace", "ClusterRole", "ClusterRoleBinding", "PersistentVolume", "StorageClass"}

workloads contains d if {
	some d in docs
	d.obj.kind in workload_kinds
}

pod_spec(obj) := obj.spec if obj.kind == "Pod"

pod_spec(obj) := obj.spec.jobTemplate.spec.template.spec if obj.kind == "CronJob"

pod_spec(obj) := obj.spec.template.spec if {
	obj.kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"}
}

containers(obj) := array.concat(object.get(pod_spec(obj), "containers", []), object.get(pod_spec(obj), "initContainers", []))

namespace(obj) := object.get(obj, ["metadata", "namespace"], "default")

is_cluster_scoped(obj) if obj.kind in cluster_scoped

ref(obj) := sprintf("%s/%s", [obj.kind, obj.metadata.name]) if is_cluster_scoped(obj)

ref(obj) := sprintf("%s/%s/%s", [obj.kind, namespace(obj), obj.metadata.name]) if not is_cluster_scoped(obj)

msg(id, d, text) := sprintf("[%s] %s @ %s :: %s", [id, ref(d.obj), d.path, text])
