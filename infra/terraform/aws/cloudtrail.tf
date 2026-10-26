# COMPLIANT: organization trail
resource "aws_cloudtrail" "org" {
  name                          = "${var.prefix}-org-trail"
  s3_bucket_name                = aws_s3_bucket.audit_trail.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.phi.arn
  tags                          = local.audit_tags

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::${local.phi_records_bucket}/"]
    }
  }
}

# NON-COMPLIANT (intentional):
#  - single region          -> PHI-AU-01  / CKV_AWS_67
#  - no log file validation -> PHI-INT-01 / CKV_AWS_36
#  - no KMS encryption      -> PHI-ENC-04 / CKV_AWS_35
resource "aws_cloudtrail" "legacy" {
  name                       = "${var.prefix}-legacy-trail"
  s3_bucket_name             = aws_s3_bucket.audit_trail.id
  is_multi_region_trail      = false
  enable_log_file_validation = false
  tags                       = local.audit_tags
}
