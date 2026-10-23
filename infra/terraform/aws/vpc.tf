############################################################
# COMPLIANT: main VPC with private subnets and flow logs
############################################################
resource "aws_vpc" "main" {
  cidr_block           = "10.20.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = merge(local.phi_tags, { Name = "${var.prefix}-main" })
}

resource "aws_subnet" "private_a" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.20.1.0/24"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = false
  tags                    = { Name = "${var.prefix}-private-a" }
}

resource "aws_subnet" "private_b" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.20.2.0/24"
  availability_zone       = "${var.region}b"
  map_public_ip_on_launch = false
  tags                    = { Name = "${var.prefix}-private-b" }
}

resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/${var.prefix}/vpc-flow-logs"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.phi.arn
}

resource "aws_iam_role" "flow_logs" {
  name = "${var.prefix}-flow-logs"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_flow_log" "main" {
  vpc_id          = aws_vpc.main.id
  traffic_type    = "ALL"
  log_destination = aws_cloudwatch_log_group.flow_logs.arn
  iam_role_arn    = aws_iam_role.flow_logs.arn
}

resource "aws_security_group" "db" {
  name        = "${var.prefix}-db"
  description = "PostgreSQL from inside the VPC only"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Postgres from VPC"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.20.0.0/16"]
  }

  egress {
    description = "VPC-internal egress"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.20.0.0/16"]
  }
}

############################################################
# NON-COMPLIANT (intentional)
#  - legacy VPC without flow logs          -> PHI-AU-03
#  - public subnet auto-assigns public IPs -> PHI-AC-06 / CKV_AWS_130
#  - DB security group open to 0.0.0.0/0   -> PHI-AC-04
############################################################
resource "aws_vpc" "legacy" {
  cidr_block = "10.30.0.0/16"
  tags       = merge(local.phi_tags, { Name = "${var.prefix}-legacy" })
}

resource "aws_subnet" "legacy_public" {
  vpc_id                  = aws_vpc.legacy.id
  cidr_block              = "10.30.1.0/24"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = true
  tags                    = { Name = "${var.prefix}-legacy-public" }
}

resource "aws_subnet" "legacy_public_b" {
  vpc_id                  = aws_vpc.legacy.id
  cidr_block              = "10.30.2.0/24"
  availability_zone       = "${var.region}b"
  map_public_ip_on_launch = true
  tags                    = { Name = "${var.prefix}-legacy-public-b" }
}

resource "aws_security_group" "legacy_db" {
  name        = "${var.prefix}-legacy-db"
  description = "Legacy reporting DB"
  vpc_id      = aws_vpc.legacy.id

  ingress {
    description = "Postgres from anywhere"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "All egress"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
