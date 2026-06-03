variable "project_name" {
  description = "Project name used as prefix for all resources"
  type        = string
}

variable "data_bucket_arn" {
  description = "ARN of the S3 data bucket"
  type        = string
  default     = ""
}

variable "kms_key_arn" {
  description = "ARN of the KMS key for the data bucket"
  type        = string
  default     = ""
}

variable "app_s3_prefix" {
  description = "S3 key prefix the application role may access"
  type        = string
  default     = "app"
}

variable "enable_github_oidc" {
  description = "Create the GitHub OIDC provider for CI/CD (set false if it already exists)"
  type        = bool
  default     = true
}

variable "github_org" {
  description = "GitHub organization name for OIDC trust"
  type        = string
  default     = "my-org"
}

variable "github_repo" {
  description = "GitHub repository name for OIDC trust"
  type        = string
  default     = "aws-s3-iam-security"
}

variable "tf_state_bucket_arn" {
  description = "ARN of the Terraform state S3 bucket"
  type        = string
  default     = ""
}

variable "tf_lock_table_arn" {
  description = "ARN of the DynamoDB table used for Terraform state locking"
  type        = string
  default     = ""
}

variable "iam_groups_requiring_mfa" {
  description = "IAM group names that should have MFA enforcement attached"
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Tags to apply to all IAM resources"
  type        = map(string)
  default     = {}
}
