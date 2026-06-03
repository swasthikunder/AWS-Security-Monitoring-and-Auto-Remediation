data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ─── SNS ALERT TOPICS ─────────────────────────────────────────────────────────
resource "aws_sns_topic" "security_alerts" {
  name = "${var.project_name}-security-alerts"
  tags = var.tags
}

resource "aws_sns_topic" "security_alerts_critical" {
  name = "${var.project_name}-security-alerts-critical"
  tags = var.tags
}

resource "aws_sns_topic_subscription" "security_email" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.security_team_email
}

resource "aws_sns_topic_subscription" "security_email_critical" {
  topic_arn = aws_sns_topic.security_alerts_critical.arn
  protocol  = "email"
  endpoint  = var.security_team_email
}

# ─── CLOUDTRAIL ───────────────────────────────────────────────────────────────
resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/${var.project_name}"
  retention_in_days = 90
  tags              = var.tags
}

resource "aws_iam_role" "cloudtrail_cwl" {
  name = "${var.project_name}-cloudtrail-cwl-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "cloudtrail_cwl" {
  name = "cloudtrail-to-cwl"
  role = aws_iam_role.cloudtrail_cwl.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
    }]
  })
}

resource "aws_cloudtrail" "security_trail" {
  name                          = "${var.project_name}-security-trail"
  s3_bucket_name                = var.log_bucket_id
  s3_key_prefix                 = "cloudtrail"
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_cwl.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true
    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3"]
    }
  }

  tags = var.tags
}

# ─── GUARDDUTY ────────────────────────────────────────────────────────────────
#resource "aws_guardduty_detector" "main" {
# enable = true
#datasources {
#  s3_logs { enable = true }
#}
#finding_publishing_frequency = "FIFTEEN_MINUTES"
#tags                         = var.tags
#}

# ─── IAM ACCESS ANALYZER ──────────────────────────────────────────────────────
resource "aws_accessanalyzer_analyzer" "account" {
  analyzer_name = "${var.project_name}-account-analyzer"
  type          = "ACCOUNT"
  tags          = var.tags
}

# ─── AWS CONFIG RECORDER ─────────────────────────────────────────────────────
#resource "aws_iam_role" "config" {
#name = "${var.project_name}-config-role"
#assume_role_policy = jsonencode({
#Version = "2012-10-17"
#Statement = [{
#Effect    = "Allow"
#Principal = { Service = "config.amazonaws.com" }
#Action    = "sts:AssumeRole"
#}]
#})
#}

#resource "aws_iam_role_policy_attachment" "config" {
#role       = aws_iam_role.config.name
#policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
#}

#resource "aws_config_configuration_recorder" "main" {
#name     = "${var.project_name}-recorder"
#role_arn = aws_iam_role.config.arn
#recording_group {
#all_supported                 = true
#include_global_resource_types = true
#}
#}

#resource "aws_config_delivery_channel" "main" {
#name           = "${var.project_name}-delivery"
#s3_bucket_name = var.log_bucket_id
#s3_key_prefix  = "aws-config"
#sns_topic_arn  = aws_sns_topic.security_alerts.arn
#snapshot_delivery_properties {
#delivery_frequency = "TwentyFour_Hours"
#}
#}

#resource "aws_config_configuration_recorder_status" "main" {
#name       = aws_config_configuration_recorder.main.name
#is_enabled = true
#depends_on = [aws_config_delivery_channel.main]
#}

# ─── AWS CONFIG RULES ─────────────────────────────────────────────────────────
#locals {
#config_rules = {
#"s3-bucket-public-read-prohibited" = {
#source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
#}
#"s3-bucket-public-write-prohibited" = {
#source_identifier = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
#}
#"s3-bucket-ssl-requests-only" = {
#source_identifier = "S3_BUCKET_SSL_REQUESTS_ONLY"
#}
#"s3-bucket-server-side-encryption-enabled" = {
#source_identifier = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
#}
#"s3-bucket-logging-enabled" = {
#source_identifier = "S3_BUCKET_LOGGING_ENABLED"
#}
#"s3-bucket-versioning-enabled" = {
#source_identifier = "S3_BUCKET_VERSIONING_ENABLED"
#}
#"iam-root-access-key-check" = {
#source_identifier = "IAM_ROOT_ACCESS_KEY_CHECK"
#}
#"root-account-mfa-enabled" = {
#source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"
#}
#"mfa-enabled-for-iam-console-access" = {
#source_identifier = "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS"
#}
#"iam-password-policy" = {
#source_identifier = "IAM_PASSWORD_POLICY"
#}
#"iam-user-unused-credentials-check" = {
#source_identifier = "IAM_USER_UNUSED_CREDENTIALS_CHECK"
#}
#"access-keys-rotated" = {
#source_identifier = "ACCESS_KEYS_ROTATED"
#}
#"cloudtrail-enabled" = {
#source_identifier = "CLOUD_TRAIL_ENABLED"
#}
#"cmk-backing-key-rotation-enabled" = {
#source_identifier = "CMK_BACKING_KEY_ROTATION_ENABLED"
#}
#}
#}

#resource "aws_config_config_rule" "rules" {
#for_each = local.config_rules
#name     = each.key
#source {
#owner             = "AWS"
#source_identifier = each.value.source_identifier
#}
#tags       = var.tags
#}

# ─── AUTO-REMEDIATION for public read ─────────────────────────────────────────
#resource "aws_config_remediation_configuration" "s3_public_read" {
#config_rule_name = aws_config_config_rule.rules["s3-bucket-public-read-prohibited"].name
#target_type      = "SSM_DOCUMENT"
#target_id        = "AWS-DisableS3BucketPublicReadWrite"
#automatic        = true
#parameter {
#name           = "BucketName"
#resource_value = "RESOURCE_ID"
#}
#retry_attempt_seconds      = 60
#maximum_automatic_attempts = 3
#}

# ─── CLOUDWATCH METRIC FILTERS ────────────────────────────────────────────────
locals {
  security_metric_filters = {
    "s3-public-access-change" = {
      pattern     = "{ ($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutPublicAccessBlock) }"
      metric_name = "S3PublicAccessChange"
    }
    "root-account-usage" = {
      pattern     = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
      metric_name = "RootAccountUsage"
    }
    "iam-policy-change" = {
      pattern     = "{ ($.eventName = PutGroupPolicy) || ($.eventName = PutRolePolicy) || ($.eventName = PutUserPolicy) || ($.eventName = CreatePolicy) || ($.eventName = DeletePolicy) || ($.eventName = AttachRolePolicy) || ($.eventName = DetachRolePolicy) }"
      metric_name = "IAMPolicyChange"
    }
    "console-login-without-mfa" = {
      pattern     = "{ ($.eventName = ConsoleLogin) && ($.additionalEventData.MFAUsed != \"Yes\") && ($.userIdentity.type != \"AssumedRole\") }"
      metric_name = "ConsoleLoginWithoutMFA"
    }
    "cloudtrail-config-change" = {
      pattern     = "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StopLogging) }"
      metric_name = "CloudTrailConfigChange"
    }
    "kms-key-deletion" = {
      pattern     = "{ ($.eventSource = kms.amazonaws.com) && (($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion)) }"
      metric_name = "KMSKeyDeletion"
    }
    "guardduty-disabled" = {
      pattern     = "{ ($.eventSource = guardduty.amazonaws.com) && ($.eventName = DeleteDetector) }"
      metric_name = "GuardDutyDisabled"
    }
    "unauthorized-api-calls" = {
      pattern     = "{ ($.errorCode = \"*UnauthorizedAccess*\") || ($.errorCode = \"AccessDenied\") }"
      metric_name = "UnauthorizedAPICalls"
    }
    "s3-bucket-deletion" = {
      pattern     = "{ $.eventName = DeleteBucket }"
      metric_name = "S3BucketDeletion"
    }
  }
}

resource "aws_cloudwatch_log_metric_filter" "security_filters" {
  for_each       = local.security_metric_filters
  name           = each.key
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = each.value.pattern
  metric_transformation {
    name          = each.value.metric_name
    namespace     = "SecurityMetrics/${var.project_name}"
    value         = "1"
    default_value = "0"
    unit          = "Count"
  }
}

resource "aws_cloudwatch_metric_alarm" "security_alarms" {
  for_each            = local.security_metric_filters
  alarm_name          = "${var.project_name}-${each.key}"
  alarm_description   = "Security event: ${each.key}"
  metric_name         = each.value.metric_name
  namespace           = "SecurityMetrics/${var.project_name}"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = contains(
    ["root-account-usage", "cloudtrail-config-change", "guardduty-disabled", "kms-key-deletion"],
    each.key
  ) ? [aws_sns_topic.security_alerts_critical.arn] : [aws_sns_topic.security_alerts.arn]

  ok_actions = [aws_sns_topic.security_alerts.arn]
  tags       = var.tags
}
