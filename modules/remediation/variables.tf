variable "project_name" {
  description = "Project name prefix"
  type        = string
}

variable "remediation_lambda_role_arn" {
  description = "ARN of the IAM role for the remediation Lambda"
  type        = string
}

variable "sns_alert_topic_arn" {
  description = "ARN of SNS topic to publish security alerts to"
  type        = string
}

variable "log_bucket_id" {
  description = "ID of the logging S3 bucket"
  type        = string
}

variable "kms_key_arn" {
  description = "Default KMS key ARN for re-encrypting non-compliant buckets"
  type        = string
  default     = ""
}

variable "dry_run" {
  description = "If true, lambda logs actions but does not make changes"
  type        = bool
  default     = false
}

variable "slack_webhook_url" {
  description = "Optional Slack webhook URL for alert notifications"
  type        = string
  default     = ""
  sensitive   = true
}

variable "auto_disable_compromised_keys" {
  description = "Automatically disable IAM access keys flagged as compromised"
  type        = bool
  default     = false
}

variable "tags" {
  description = "Tags to apply to all remediation resources"
  type        = map(string)
  default     = {}
}
