data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ─── PERMISSION BOUNDARY ──────────────────────────────────────────────────────
# Sets the maximum permissions ceiling any app role may ever have.
resource "aws_iam_policy" "permission_boundary" {
  name        = "${var.project_name}-permission-boundary"
  description = "Maximum permissions ceiling for all application roles"
  path        = "/boundaries/"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowScopedS3Access"
        Effect = "Allow"
        Action = [
          "s3:GetObject", "s3:PutObject", "s3:DeleteObject",
          "s3:ListBucket", "s3:GetBucketLocation",
          "s3:GetBucketVersioning", "s3:GetEncryptionConfiguration"
        ]
        Resource = [
          "arn:aws:s3:::${var.project_name}-*",
          "arn:aws:s3:::${var.project_name}-*/*"
        ]
      },
      #{
      #Sid    = "AllowKMSForEncryption"
      #Effect = "Allow"
      #Action = ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
      #Resource = "arn:aws:kms:*:${data.aws_caller_identity.current.account_id}:key/*"
      #},
      {
        Sid    = "AllowCloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup", "logs:CreateLogStream",
          "logs:PutLogEvents", "logs:DescribeLogStreams"
        ]
        Resource = "arn:aws:logs:*:${data.aws_caller_identity.current.account_id}:*"
      },
      {
        Sid      = "AllowSecretsFetch"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
        Resource = "arn:aws:secretsmanager:*:${data.aws_caller_identity.current.account_id}:secret:${var.project_name}/*"
      },
      # Hard denies — these can NEVER be done regardless of other policies
      {
        Sid    = "DenyIAMEscalation"
        Effect = "Deny"
        Action = [
          "iam:CreateUser", "iam:CreateAccessKey",
          "iam:AttachUserPolicy", "iam:AttachRolePolicy",
          "iam:PutUserPolicy", "iam:PutRolePolicy",
          "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion",
          "iam:PassRole", "iam:UpdateAssumeRolePolicy"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyDisableSecurityServices"
        Effect = "Deny"
        Action = [
          "guardduty:DeleteDetector",
          "cloudtrail:DeleteTrail", "cloudtrail:StopLogging",
          "config:DeleteConfigRule", "config:StopConfigurationRecorder",
          "securityhub:DisableSecurityHub",
          "access-analyzer:DeleteAnalyzer"
        ]
        Resource = "*"
      }
    ]
  })
}

# ─── APPLICATION ROLE (Least Privilege) ──────────────────────────────────────
resource "aws_iam_role" "app_role" {
  name                 = "${var.project_name}-app-role"
  description          = "Application role with least-privilege S3 access"
  max_session_duration = 3600
  permissions_boundary = aws_iam_policy.permission_boundary.arn
  path                 = "/application/"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowEC2Assumption"
        Effect    = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
        Action    = "sts:AssumeRole"
      },
      {
        Sid       = "AllowLambdaAssumption"
        Effect    = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "app_s3_read" {
  name = "s3-scoped-access"
  role = aws_iam_role.app_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ListTargetBucket"
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = var.data_bucket_arn
        Condition = {
          StringLike = { "s3:prefix" = ["${var.app_s3_prefix}/*", ""] }
        }
      },
      {
        Sid      = "ReadWriteScopedPrefix"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject", "s3:PutObjectTagging"]
        Resource = "${var.data_bucket_arn}/${var.app_s3_prefix}/*"
      },
      #{
      #Sid    = "UseKMSKey"
      #Effect = "Allow"
      #Action = ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
      #Resource = var.kms_key_arn
      #Condition = {
      #StringEquals = {
      #"kms:ViaService" = "s3.${data.aws_region.current.name}.amazonaws.com"
      #}
      #}
      #}
    ]
  })
}

# ─── REMEDIATION LAMBDA ROLE ──────────────────────────────────────────────────
resource "aws_iam_role" "remediation_lambda" {
  name        = "${var.project_name}-remediation-lambda-role"
  description = "Execution role for auto-remediation Lambda"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  permissions_boundary = aws_iam_policy.permission_boundary.arn
  tags                 = var.tags
}

resource "aws_iam_role_policy" "remediation_lambda" {
  name = "remediation-permissions"
  role = aws_iam_role.remediation_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3RemediationActions"
        Effect = "Allow"
        Action = [
          "s3:GetBucketPolicy", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy",
          "s3:GetBucketAcl", "s3:PutBucketAcl",
          "s3:GetPublicAccessBlock", "s3:PutPublicAccessBlock",
          "s3:GetBucketLogging", "s3:PutBucketLogging",
          "s3:GetEncryptionConfiguration", "s3:PutEncryptionConfiguration",
          "s3:ListAllMyBuckets", "s3:GetBucketTagging", "s3:PutBucketTagging"
        ]
        Resource = "*"
      },
      {
        Sid      = "AccountLevelS3Block"
        Effect   = "Allow"
        Action   = ["s3:GetAccountPublicAccessBlock", "s3:PutAccountPublicAccessBlock"]
        Resource = "*"
      },
      {
        Sid    = "IAMReadForAudit"
        Effect = "Allow"
        Action = [
          "iam:ListUsers",
          "iam:ListAccessKeys",
          "iam:UpdateAccessKey",
          "iam:GetUser"
        ]    
        Resource = "*"
      },
      {
        Sid    = "SQSAccess"
        Effect = "Allow"
        Action = [
          "sqs:SendMessage"
        ]
        Resource = "*"
      },
      #{
        #Sid    = "GuardDutyRead"
        #Effect = "Allow"
        #Action = ["guardduty:GetFindings", "guardduty:ListFindings"]
        #Resource = "*"
      #},
      {
        Sid      = "SNSPublish"
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = "*"
      },
      {
        Sid      = "CloudWatchLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:${data.aws_caller_identity.current.account_id}:*"
      }
    ]
  }
  )
}




# ─── CI/CD ROLE (OIDC – No Static Keys) ──────────────────────────────────────
resource "aws_iam_openid_connect_provider" "github" {
  count           = var.enable_github_oidc ? 1 : 0
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

resource "aws_iam_role" "cicd_role" {
  count = var.enable_github_oidc ? 1 : 0
  name        = "${var.project_name}-cicd-role"
  description = "CI/CD role assumed via GitHub OIDC - no static AWS keys needed"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowGitHubOIDC"
        Effect = "Allow"
        Principal = {
          Federated = var.enable_github_oidc ? aws_iam_openid_connect_provider.github[0].arn : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          }
          StringLike = {
            "token.actions.githubusercontent.com:sub" = "repo:${var.github_org}/${var.github_repo}:*"
          }
        }
      }
    ]
  })

  permissions_boundary = aws_iam_policy.permission_boundary.arn
  tags                 = var.tags
}

resource "aws_iam_role_policy" "cicd_terraform" {
  count = var.enable_github_oidc ? 1 : 0
  name = "terraform-deploy"
  role = aws_iam_role.cicd_role[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "TerraformStateAccess"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:DeleteObject"]
        Resource = [var.tf_state_bucket_arn, "${var.tf_state_bucket_arn}/env:/*"]
      },
      {
        Sid      = "TerraformLockAccess"
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem", "dynamodb:DescribeTable"]
        Resource = var.tf_lock_table_arn
      },
      #{
      #Sid    = "ReadSecurityFindings"
      #Effect = "Allow"
      #Action = [
      #"config:GetComplianceDetailsByConfigRule",
      #"securityhub:GetFindings",
      #"guardduty:ListFindings", "guardduty:GetFindings",
      #"access-analyzer:ListFindings"
      #]
      #Resource = "*"
      #}
    ]
  })
}

# ─── MFA ENFORCEMENT POLICY ───────────────────────────────────────────────────
resource "aws_iam_policy" "mfa_enforcement" {
  name        = "${var.project_name}-mfa-enforcement"
  description = "Deny all actions when MFA is not present"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowSelfServiceMFAManagement"
        Effect = "Allow"
        Action = [
          "iam:CreateVirtualMFADevice", "iam:EnableMFADevice",
          "iam:GetUser", "iam:ListMFADevices",
          "iam:ListVirtualMFADevices", "iam:ResyncMFADevice",
          "sts:GetSessionToken"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyAllWithoutMFA"
        Effect = "Deny"
        NotAction = [
          "iam:CreateVirtualMFADevice", "iam:EnableMFADevice",
          "iam:GetUser", "iam:ListMFADevices",
          "iam:ListVirtualMFADevices", "iam:ResyncMFADevice",
          "sts:GetSessionToken"
        ]
        Resource = "*"
        Condition = {
          BoolIfExists = { "aws:MultiFactorAuthPresent" = "false" }
        }
      }
    ]
  })
}

# ─── IAM PASSWORD POLICY ──────────────────────────────────────────────────────
resource "aws_iam_account_password_policy" "strong" {
  minimum_password_length        = 16
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 24
  hard_expiry                    = false
}
