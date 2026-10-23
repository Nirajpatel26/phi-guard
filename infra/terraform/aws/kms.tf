# COMPLIANT: customer-managed key with annual rotation.
resource "aws_kms_key" "phi" {
  description             = "CMK for PHI data at rest (S3, RDS, CloudTrail)"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags                    = local.phi_tags
}

resource "aws_kms_alias" "phi" {
  name          = "alias/${var.prefix}-phi"
  target_key_id = aws_kms_key.phi.key_id
}

# NON-COMPLIANT (intentional): rotation disabled -> PHI-ENC-03 / CKV_AWS_7
resource "aws_kms_key" "legacy" {
  description             = "Legacy reporting key"
  enable_key_rotation     = false
  deletion_window_in_days = 7
  tags                    = local.phi_tags
}
