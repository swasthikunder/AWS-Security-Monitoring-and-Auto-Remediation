output "cloudtrail_arn" {
  description = "ARN of the CloudTrail trail"
  value       = aws_cloudtrail.security_trail.arn
}

output "access_analyzer_arn" {
  description = "ARN of the IAM Access Analyzer"
  value       = aws_accessanalyzer_analyzer.account.arn
}

output "security_alerts_topic_arn" {
  description = "ARN of the security alerts SNS topic"
  value       = aws_sns_topic.security_alerts.arn
}

output "security_alerts_critical_topic_arn" {
  description = "ARN of the critical security alerts SNS topic"
  value       = aws_sns_topic.security_alerts_critical.arn
}

output "cloudtrail_log_group_name" {
  description = "Name of the CloudTrail CloudWatch log group"
  value       = aws_cloudwatch_log_group.cloudtrail.name
}

# -------------------------------------------------------
# ENTERPRISE FEATURES (DISABLED FOR FREE-TIER DEPLOYMENT)
# -------------------------------------------------------

# output "guardduty_detector_id" {
#   description = "ID of the GuardDuty detector"
#   value       = aws_guardduty_detector.main.id
# }