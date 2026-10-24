############################################################
# COMPLIANT: primary PHI bucket
############################################################
resource "aws_s3_bucket" "phi_records" {
  bucket = local.phi_records_bucket
  tags   = local.phi_tags
}

resource "aws_s3_bucket_public_access_block" "phi_records" {
  bucket                  = aws_s3_bucket.phi_records.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "phi_records" {
  bucket = aws_s3_bucket.phi_records.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.phi.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "phi_records" {
  bucket = aws_s3_bucket.phi_records.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "phi_records" {
  bucket        = aws_s3_bucket.phi_records.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "phi-records/"
}

resource "aws_s3_bucket_policy" "phi_records" {
  bucket = aws_s3_bucket.phi_records.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource = [
        "arn:aws:s3:::${local.phi_records_bucket}",
        "arn:aws:s3:::${local.phi_records_bucket}/*",
      ]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

############################################################
# COMPLIANT: server access log target. S3 server access logs cannot be
# delivered to an SSE-KMS bucket, so this one uses SSE-S3 and is classified
# "internal" (out of scope for the KMS control).
############################################################
resource "aws_s3_bucket" "access_logs" {
  bucket = local.access_logs_bucket
  tags = {
    data-classification = "internal"
    managed-by          = "terraform"
  }
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket                  = aws_s3_bucket.access_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

############################################################
# COMPLIANT: CloudTrail destination
############################################################
resource "aws_s3_bucket" "audit_trail" {
  bucket = local.audit_trail_bucket
  tags   = local.audit_tags
}

resource "aws_s3_bucket_public_access_block" "audit_trail" {
  bucket                  = aws_s3_bucket.audit_trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_trail" {
  bucket = aws_s3_bucket.audit_trail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.phi.arn
    }
  }
}

resource "aws_s3_bucket_versioning" "audit_trail" {
  bucket = aws_s3_bucket.audit_trail.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_policy" "audit_trail" {
  bucket = aws_s3_bucket.audit_trail.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          "arn:aws:s3:::${local.audit_trail_bucket}",
          "arn:aws:s3:::${local.audit_trail_bucket}/*",
        ]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = "arn:aws:s3:::${local.audit_trail_bucket}"
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "arn:aws:s3:::${local.audit_trail_bucket}/AWSLogs/${var.account_id}/*"
        Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } }
      },
    ]
  })
}

############################################################
# NON-COMPLIANT (intentional): legacy export bucket holding PHI
#  - no public access block           -> PHI-AC-01
#  - public-read ACL                  -> PHI-AC-05
#  - SSE-S3 instead of KMS            -> PHI-ENC-01
#  - no access logging                -> PHI-AU-02
#  - no versioning                    -> PHI-INT-02
#  - no TLS-only bucket policy        -> PHI-TX-01
############################################################
resource "aws_s3_bucket" "legacy_exports" {
  bucket = local.legacy_exports_bucket
  tags   = local.phi_tags
}

resource "aws_s3_bucket_ownership_controls" "legacy_exports" {
  bucket = aws_s3_bucket.legacy_exports.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "legacy_exports" {
  depends_on = [aws_s3_bucket_ownership_controls.legacy_exports]
  bucket     = aws_s3_bucket.legacy_exports.id
  acl        = "public-read"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "legacy_exports" {
  bucket = aws_s3_bucket.legacy_exports.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
