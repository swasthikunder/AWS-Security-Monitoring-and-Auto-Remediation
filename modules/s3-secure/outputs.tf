output "data_bucket_id" {
  description = "ID of the secure data bucket"
  value       = aws_s3_bucket.data.id
}

output "data_bucket_arn" {
  description = "ARN of the secure data bucket"
  value       = aws_s3_bucket.data.arn
}

output "log_bucket_id" {
  description = "ID of the logging bucket"
  value       = aws_s3_bucket.logs.id
}

output "log_bucket_arn" {
  description = "ARN of the logging bucket"
  value       = aws_s3_bucket.logs.arn
}

# ==========================================================
# ENTERPRISE FEATURE (DISABLED FOR FREE-TIER DEPLOYMENT)
# ==========================================================

# output "kms_data_key_arn" {
#   description = "ARN of the KMS key for data bucket encryption"
#   value       = aws_kms_key.data_bucket.arn
# }

# output "kms_log_key_arn" {
#   description = "ARN of the KMS key for log bucket encryption"
#   value       = aws_kms_key.log_bucket.arn
# }

output "security_summary" {
  description = "Security posture summary"

  value = {
    bucket_name           = local.bucket_name
    public_access_blocked = true
    encryption            = "AES256"
    versioning            = "Enabled"
    access_logging        = "Enabled"
    https_enforced        = true
    acls                  = "Disabled (BucketOwnerEnforced)"
  }
}