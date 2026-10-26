############################################################
# COMPLIANT: least-privilege application policy
############################################################
resource "aws_iam_policy" "app_read_phi" {
  name        = "${var.prefix}-app-read-phi"
  description = "Read-only access to the PHI records bucket"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadPhiObjects"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:ListBucket"]
        Resource = ["arn:aws:s3:::${local.phi_records_bucket}", "arn:aws:s3:::${local.phi_records_bucket}/*"]
      },
      {
        Sid       = "DecryptViaS3Only"
        Effect    = "Allow"
        Action    = ["kms:Decrypt"]
        Resource  = "*"
        Condition = { StringEquals = { "kms:ViaService" = "s3.${var.region}.amazonaws.com" } }
      },
    ]
  })
}

resource "aws_iam_role" "app" {
  name = "${var.prefix}-app"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "app_read_phi" {
  role       = aws_iam_role.app.name
  policy_arn = aws_iam_policy.app_read_phi.arn
}

resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  password_reuse_prevention      = 24
  max_password_age               = 90
}

############################################################
# NON-COMPLIANT (intentional): wildcard admin -> PHI-AC-03
############################################################
resource "aws_iam_policy" "break_glass_admin" {
  name        = "${var.prefix}-break-glass-admin"
  description = "Legacy 'temporary' admin policy that never got removed"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}
