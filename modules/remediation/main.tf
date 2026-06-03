data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

data "archive_file" "remediation_lambda" {
  type        = "zip"
  source_dir  = "${path.root}/../../lambda/remediation"
  output_path = "${path.module}/lambda_remediation.zip"
}

# ─── REMEDIATION LAMBDA ───────────────────────────────────────────────────────
resource "aws_lambda_function" "remediation" {
  filename         = data.archive_file.remediation_lambda.output_path
  function_name    = "${var.project_name}-auto-remediation"
  role             = var.remediation_lambda_role_arn
  handler          = "handler.lambda_handler"
  runtime          = "python3.11"
  timeout          = 300
  memory_size      = 256
  source_code_hash = data.archive_file.remediation_lambda.output_base64sha256

  depends_on = [
    aws_sqs_queue.remediation_dlq
  ]

  environment {
    variables = {
      SNS_ALERT_TOPIC_ARN           = var.sns_alert_topic_arn
      LOG_BUCKET_NAME               = var.log_bucket_id
      DEFAULT_KMS_KEY_ARN           = var.kms_key_arn
      AWS_ACCOUNT_ID                = data.aws_caller_identity.current.account_id
      DRY_RUN                       = var.dry_run ? "true" : "false"
      SLACK_WEBHOOK_URL             = var.slack_webhook_url
      AUTO_DISABLE_COMPROMISED_KEYS = var.auto_disable_compromised_keys ? "true" : "false"
    }
  }

  #dead_letter_config {
  #  target_arn = aws_sqs_queue.remediation_dlq.arn
  #}

  #reserved_concurrent_executions = 1

  tags = var.tags
}

# Dead-letter queue for failed invocations
resource "aws_sqs_queue" "remediation_dlq" {
  name                      = "${var.project_name}-remediation-dlq"
  message_retention_seconds = 86400
  tags                      = var.tags
}

resource "aws_cloudwatch_log_group" "remediation_lambda" {
  name              = "/aws/lambda/${aws_lambda_function.remediation.function_name}"
  retention_in_days = 30
  tags              = var.tags
}

# ─── EVENTBRIDGE RULES ────────────────────────────────────────────────────────
# Trigger on GuardDuty HIGH/CRITICAL findings
#resource "aws_cloudwatch_event_rule" "guardduty_findings" {
#name        = "${var.project_name}-guardduty-findings"
#description = "Trigger remediation on GuardDuty HIGH/CRITICAL S3 and IAM findings"

#event_pattern = jsonencode({
#source      = ["aws.guardduty"]
#detail-type = ["GuardDuty Finding"]
#detail = {
#severity = [{ numeric = [">=", 7] }]
#}
#})

#tags = var.tags
#}

#resource "aws_cloudwatch_event_target" "guardduty_to_lambda" {
#rule      = aws_cloudwatch_event_rule.guardduty_findings.name
#target_id = "RemediationLambda"
#arn       = aws_lambda_function.remediation.arn
#}

#resource "aws_lambda_permission" "eventbridge_guardduty" {
#statement_id  = "AllowEventBridgeGuardDuty"
#action        = "lambda:InvokeFunction"
#function_name = aws_lambda_function.remediation.function_name
#principal     = "events.amazonaws.com"
#source_arn    = aws_cloudwatch_event_rule.guardduty_findings.arn
#}

# Trigger on Config compliance changes
#resource "aws_cloudwatch_event_rule" "config_noncompliance" {
#name        = "${var.project_name}-config-noncompliance"
#description = "Trigger remediation on AWS Config NON_COMPLIANT events"

#event_pattern = jsonencode({
#source      = ["aws.config"]
#detail-type = ["Config Rules Compliance Change"]
#detail = {
#newEvaluationResult = {
#complianceType = ["NON_COMPLIANT"]
#}
#}
#})

#tags = var.tags
#}

#resource "aws_cloudwatch_event_target" "config_to_lambda" {
#rule      = aws_cloudwatch_event_rule.config_noncompliance.name
#target_id = "RemediationLambda"
#arn       = aws_lambda_function.remediation.arn
#}

#resource "aws_lambda_permission" "eventbridge_config" {
#statement_id  = "AllowEventBridgeConfig"
#action        = "lambda:InvokeFunction"
#function_name = aws_lambda_function.remediation.function_name
#principal     = "events.amazonaws.com"
#source_arn    = aws_cloudwatch_event_rule.config_noncompliance.arn
#}

# Trigger on S3 bucket policy changes (CloudTrail API events)
resource "aws_cloudwatch_event_rule" "s3_policy_change" {
  name        = "${var.project_name}-s3-policy-change"
  description = "React to S3 bucket policy/ACL/public-access changes in real time"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName = [
        "PutBucketPolicy",
        "PutBucketAcl",
        "PutPublicAccessBlock",
        "DeletePublicAccessBlock",
        "DeleteBucketPolicy"
      ]
    }
  })

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "s3_change_to_lambda" {
  rule      = aws_cloudwatch_event_rule.s3_policy_change.name
  target_id = "RemediationLambda"
  arn       = aws_lambda_function.remediation.arn
}

resource "aws_lambda_permission" "eventbridge_s3" {
  statement_id  = "AllowEventBridgeS3"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediation.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.s3_policy_change.arn
}
