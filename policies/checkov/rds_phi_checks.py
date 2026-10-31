"""Custom Terraform checks where Checkov has no built-in equivalent we want to rely on.

CKV_PHI_AWS_1  RDS deletion protection         -> PHI-INT-03, 45 CFR §164.312(c)(1)
CKV_PHI_AWS_2  RDS IAM database authentication -> PHI-AUTH-01, 45 CFR §164.312(d)

A missing attribute counts as FAILED (both default to false in AWS).
"""
from checkov.common.models.enums import CheckCategories
from checkov.terraform.checks.resource.base_resource_value_check import BaseResourceValueCheck


class RdsDeletionProtection(BaseResourceValueCheck):
    def __init__(self) -> None:
        super().__init__(
            name="PHI Guard: RDS instance holding PHI has deletion protection enabled",
            id="CKV_PHI_AWS_1",
            categories=[CheckCategories.BACKUP_AND_RECOVERY],
            supported_resources=["aws_db_instance", "aws_rds_cluster"],
        )

    def get_inspected_key(self) -> str:
        return "deletion_protection"


class RdsIamAuthentication(BaseResourceValueCheck):
    def __init__(self) -> None:
        super().__init__(
            name="PHI Guard: RDS instance uses IAM database authentication",
            id="CKV_PHI_AWS_2",
            categories=[CheckCategories.IAM],
            supported_resources=["aws_db_instance", "aws_rds_cluster"],
        )

    def get_inspected_key(self) -> str:
        return "iam_database_authentication_enabled"


deletion_check = RdsDeletionProtection()
iam_auth_check = RdsIamAuthentication()
