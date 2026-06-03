variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name used as resource prefix"
  type        = string
  default     = "s3iam-sec"
}

variable "data_classification" {
  description = "Data classification level"
  type        = string
  default     = "Internal"
}

variable "compliance_frameworks" {
  description = "Compliance frameworks"
  type        = list(string)
  default     = ["CIS", "SOC2"]
}

variable "security_team_email" {
  description = "Email address for SNS alerts"
  type        = string
}

variable "enable_github_oidc" {
  description = "Enable GitHub OIDC role"
  type        = bool
  default     = false
}

variable "github_org" {
  description = "GitHub organization"
  type        = string
  default     = "my-org"
}

variable "github_repo" {
  description = "GitHub repository"
  type        = string
  default     = "aws-s3-iam-security"
}

variable "tf_state_bucket_arn" {
  description = "Terraform state bucket ARN"
  type        = string
  default     = ""
}

variable "tf_lock_table_arn" {
  description = "Terraform lock table ARN"
  type        = string
  default     = ""
}

variable "slack_webhook_url" {
  description = "Slack webhook URL"
  type        = string
  default     = ""
  sensitive   = true
}