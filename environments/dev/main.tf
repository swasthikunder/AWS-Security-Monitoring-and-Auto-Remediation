terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = "dev"
      ManagedBy   = "Terraform"
    }
  }
}

# ==========================================================
# S3 SECURITY MODULE
# ==========================================================
module "s3_secure" {
  source = "../../modules/s3-secure"

  bucket_name_prefix                 = "${var.project_name}-dev"
  data_classification                = var.data_classification
  compliance_frameworks              = var.compliance_frameworks
  log_retention_days                 = 365
  manage_account_public_access_block = true

  allowed_role_arns = [
    module.iam_hardened.app_role_arn
  ]

  log_admin_role_arn = module.iam_hardened.app_role_arn

  tags = {
    Environment = "dev"
  }
}

# ==========================================================
# IAM HARDENING MODULE
# ==========================================================
module "iam_hardened" {
  source = "../../modules/iam-hardened"

  project_name    = var.project_name
  data_bucket_arn = module.s3_secure.data_bucket_arn

  # Enterprise Feature (Disabled)
  # kms_key_arn = module.s3_secure.kms_data_key_arn

  app_s3_prefix       = "app"
  enable_github_oidc  = var.enable_github_oidc
  github_org          = var.github_org
  github_repo         = var.github_repo
  tf_state_bucket_arn = var.tf_state_bucket_arn
  tf_lock_table_arn   = var.tf_lock_table_arn

  tags = {
    Environment = "dev"
  }
}

# ==========================================================
# SECURITY MONITORING
# ==========================================================
module "security_monitoring" {
  source = "../../modules/security-monitoring"

  project_name        = var.project_name
  log_bucket_id       = module.s3_secure.log_bucket_id
  security_team_email = var.security_team_email

  tags = {
    Environment = "dev"
  }
}

# ==========================================================
# REMEDIATION
# ==========================================================
module "remediation" {
  source = "../../modules/remediation"

  project_name                = var.project_name
  remediation_lambda_role_arn = module.iam_hardened.remediation_lambda_role_arn

  sns_alert_topic_arn = module.security_monitoring.security_alerts_topic_arn
  log_bucket_id       = module.s3_secure.log_bucket_id

  # Enterprise Feature (Disabled)
  # kms_key_arn = module.s3_secure.kms_data_key_arn

  dry_run                       = true
  slack_webhook_url             = var.slack_webhook_url
  auto_disable_compromised_keys = false

  tags = {
    Environment = "dev"
  }
}