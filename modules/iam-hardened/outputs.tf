output "app_role_arn" {
  description = "ARN of the application IAM role"
  value       = aws_iam_role.app_role.arn
}

output "app_role_name" {
  description = "Name of the application IAM role"
  value       = aws_iam_role.app_role.name
}

output "remediation_lambda_role_arn" {
  description = "ARN of the remediation Lambda execution role"
  value       = aws_iam_role.remediation_lambda.arn
}

output "cicd_role_arn" {
  description = "ARN of the CI/CD role"
  value       = var.enable_github_oidc ? aws_iam_role.cicd_role[0].arn : null
}

output "permission_boundary_arn" {
  description = "ARN of the permission boundary policy"
  value       = aws_iam_policy.permission_boundary.arn
}

output "mfa_enforcement_policy_arn" {
  description = "ARN of the MFA enforcement policy"
  value       = aws_iam_policy.mfa_enforcement.arn
}
