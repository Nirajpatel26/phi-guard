resource "aws_db_subnet_group" "phi" {
  name       = "${var.prefix}-phi"
  subnet_ids = [aws_subnet.private_a.id, aws_subnet.private_b.id]
}

resource "aws_db_parameter_group" "phi_pg" {
  name   = "${var.prefix}-phi-pg16"
  family = "postgres16"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }

  parameter {
    name  = "log_connections"
    value = "1"
  }
}

############################################################
# COMPLIANT: primary PHI database
############################################################
resource "aws_db_instance" "phi_primary" {
  identifier                          = "${var.prefix}-phi-primary"
  engine                              = "postgres"
  engine_version                      = "16.4"
  instance_class                      = "db.t4g.medium"
  allocated_storage                   = 50
  db_name                             = "ehr"
  username                            = "ehr_admin"
  manage_master_user_password         = true # password lives in Secrets Manager, not in code
  storage_encrypted                   = true
  kms_key_id                          = aws_kms_key.phi.arn
  publicly_accessible                 = false
  iam_database_authentication_enabled = true
  deletion_protection                 = true
  backup_retention_period             = 14
  multi_az                            = true
  enabled_cloudwatch_logs_exports     = ["postgresql", "upgrade"]
  parameter_group_name                = aws_db_parameter_group.phi_pg.name
  db_subnet_group_name                = aws_db_subnet_group.phi.name
  vpc_security_group_ids              = [aws_security_group.db.id]
  auto_minor_version_upgrade          = true
  copy_tags_to_snapshot               = true
  skip_final_snapshot                 = false
  final_snapshot_identifier           = "${var.prefix}-phi-primary-final"
  tags                                = local.phi_tags
}

############################################################
# NON-COMPLIANT (intentional): legacy reporting replica
#  - unencrypted storage            -> PHI-ENC-02 / CKV_AWS_16
#  - publicly accessible            -> PHI-AC-02  / CKV_AWS_17
#  - no IAM DB auth                 -> PHI-AUTH-01 / CKV_PHI_AWS_2
#  - no deletion protection         -> PHI-INT-03 / CKV_PHI_AWS_1
#  - 1-day backups                  -> PHI-INT-04
#  - no log exports                 -> PHI-AU-04
#  - default parameter group (TLS not forced) -> PHI-TX-02
############################################################
resource "aws_db_instance" "legacy_reporting" {
  identifier                  = "${var.prefix}-legacy-reporting"
  engine                      = "postgres"
  engine_version              = "16.4"
  instance_class              = "db.t4g.small"
  allocated_storage           = 20
  db_name                     = "reporting"
  username                    = "report_admin"
  manage_master_user_password = true
  storage_encrypted           = false
  publicly_accessible         = true
  backup_retention_period     = 1
  parameter_group_name        = "default.postgres16"
  vpc_security_group_ids      = [aws_security_group.legacy_db.id]
  skip_final_snapshot         = true
  tags                        = local.phi_tags
}
