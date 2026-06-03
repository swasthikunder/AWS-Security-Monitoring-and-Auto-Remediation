output "data_bucket_name" {
  description = "Name of the secured S3 data bucket"
  value       = module.s3_secure.data_bucket_id
}

output "data_bucket_arn" {
  description = "ARN of the secured S3 data bucket"
  value       = module.s3_secure.data_bucket_arn
}

output "log_bucket_name" {
  description = "Name of the logging bucket"
  value       = module.s3_secure.log_bucket_id
}

output "app_role_arn" {
  description = "ARN of the least-privilege app IAM role"
  value       = module.iam_hardened.app_role_arn
}

output "cicd_role_arn" {
  description = "ARN of the CI/CD OIDC role"
  value       = module.iam_hardened.cicd_role_arn
}

output "security_summary" {
  description = "Full security posture summary"
  value       = module.s3_secure.security_summary
}

output "remediation_lambda_arn" {
  description = "ARN of the auto-remediation Lambda"
  value       = module.remediation.remediation_lambda_arn
}

# ==========================================================
# ENTERPRISE FEATURES (DISABLED FOR FREE-TIER DEPLOYMENT)
# ==========================================================

# output "kms_data_key_arn" {
#   description = "ARN of the KMS key for data encryption"
#   value       = module.s3_secure.kms_data_key_arn
# }

# output "guardduty_detector_id" {
#   description = "GuardDuty detector ID"
#   value       = module.security_monitoring.guardduty_detector_id
# }