variable "bucket_name_prefix" {
  description = "Prefix for S3 bucket name (a random hex suffix is appended)"
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,55}[a-z0-9]$", var.bucket_name_prefix))
    error_message = "Bucket name prefix must be 3-57 lowercase alphanumeric chars or hyphens."
  }
}

variable "data_classification" {
  description = "Data classification level"
  type        = string
  default     = "Internal"
  validation {
    condition     = contains(["PII", "PHI", "PCI", "Internal", "Public"], var.data_classification)
    error_message = "Must be one of: PII, PHI, PCI, Internal, Public."
  }
}

variable "compliance_frameworks" {
  description = "List of applicable compliance frameworks"
  type        = list(string)
  default     = ["SOC2"]
}

variable "log_retention_days" {
  description = "Number of days to retain logs (365 for PCI, 2190 for HIPAA 6yr)"
  type        = number
  default     = 365
  validation {
    condition     = var.log_retention_days >= 90 && var.log_retention_days <= 2555
    error_message = "Log retention must be between 90 and 2555 days."
  }
}

variable "enable_mfa_delete" {
  description = "Enable MFA Delete on data bucket (requires root CLI command after apply)"
  type        = bool
  default     = false
}

variable "allowed_role_arns" {
  description = "List of IAM role ARNs allowed to access the data bucket"
  type        = list(string)
  default     = []
}

variable "allowed_vpc_endpoint_ids" {
  description = "VPC endpoint IDs allowed to access data bucket"
  type        = list(string)
  default     = []
}

variable "log_admin_role_arn" {
  description = "ARN of the security role allowed to delete logs (break-glass)"
  type        = string
  default     = ""
}

variable "manage_account_public_access_block" {
  description = "Whether to manage account-level S3 public access block"
  type        = bool
  default     = true
}

variable "enable_object_lock" {
  description = "Enable S3 Object Lock (WORM) on logs bucket"
  type        = bool
  default     = false
}

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}
