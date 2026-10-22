# Kubernetes provider pointed at the local kind cluster. Optional: `make tf-kind-plan`
# shows how cluster-level guardrails (quota + limit range in the PHI namespace) can
# be managed as code. `make up` creates the namespaces itself with kubectl, so this
# root is independent of the demo path. Nothing here touches a cloud account.
terraform {
  required_version = ">= 1.6.0"
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.35"
    }
  }
}

variable "kubeconfig" {
  type    = string
  default = "~/.kube/config"
}

provider "kubernetes" {
  config_path    = pathexpand(var.kubeconfig)
  config_context = "kind-phi-guard"
}

resource "kubernetes_resource_quota_v1" "phi" {
  metadata {
    name      = "phi-quota"
    namespace = "phi"
  }
  spec {
    hard = {
      "pods"            = "30"
      "limits.cpu"      = "4"
      "limits.memory"   = "4Gi"
      "requests.cpu"    = "2"
      "requests.memory" = "2Gi"
    }
  }
}

resource "kubernetes_limit_range_v1" "phi" {
  metadata {
    name      = "phi-defaults"
    namespace = "phi"
  }
  spec {
    limit {
      type = "Container"
      default = {
        cpu    = "250m"
        memory = "256Mi"
      }
      default_request = {
        cpu    = "50m"
        memory = "96Mi"
      }
    }
  }
}
