output "remediation_lambda_arn" {
  description = "ARN of the auto-remediation Lambda function"
  value       = aws_lambda_function.remediation.arn
}

output "remediation_lambda_name" {
  description = "Name of the auto-remediation Lambda function"
  value       = aws_lambda_function.remediation.function_name
}

output "remediation_dlq_url" {
  description = "URL of the remediation dead-letter SQS queue"
  value       = aws_sqs_queue.remediation_dlq.url
}
