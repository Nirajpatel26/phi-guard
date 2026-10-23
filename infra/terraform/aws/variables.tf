variable "region" {
  type    = string
  default = "us-east-1"
}

variable "prefix" {
  type    = string
  default = "phiguard-demo"
}

# Dummy account id used to build ARNs as plain strings, which keeps policy
# documents known at plan time so the Rego policies can inspect them.
variable "account_id" {
  type    = string
  default = "123456789012"
}

locals {
  phi_tags = {
    data-classification = "phi"
    owner               = "ehr-platform"
    managed-by          = "terraform"
  }
  audit_tags = {
    data-classification = "audit"
    owner               = "security"
    managed-by          = "terraform"
  }

  phi_records_bucket    = "${var.prefix}-phi-records"
  access_logs_bucket    = "${var.prefix}-access-logs"
  audit_trail_bucket    = "${var.prefix}-audit-trail"
  legacy_exports_bucket = "${var.prefix}-legacy-exports"
}
