variable "project_name" {
  description = "Project name prefix"
  type        = string
}

variable "log_bucket_id" {
  description = "ID of the S3 logging bucket"
  type        = string
}

variable "logs_kms_key_arn" {
  description = "ARN of KMS key used for log encryption"
  type        = string
  default     = ""
}

variable "security_team_email" {
  description = "Email address for security alert subscriptions"
  type        = string
}

variable "compliance_frameworks" {
  description = "Compliance frameworks to enable"
  type        = list(string)
  default     = ["CIS"]
}

variable "is_organization_trail" {
  description = "Whether to create an organization-level CloudTrail"
  type        = bool
  default     = false
}

variable "enable_eks_protection" {
  description = "Enable GuardDuty EKS audit log monitoring"
  type        = bool
  default     = false
}

variable "tags" {
  description = "Tags to apply to all monitoring resources"
  type        = map(string)
  default     = {}
}