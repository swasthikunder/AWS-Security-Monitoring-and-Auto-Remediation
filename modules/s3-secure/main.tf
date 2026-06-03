terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
}

resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  bucket_name     = "${var.bucket_name_prefix}-${random_id.suffix.hex}"
  log_bucket_name = "${var.bucket_name_prefix}-logs-${random_id.suffix.hex}"

  common_tags = merge(var.tags, {
    ManagedBy        = "Terraform"
    SecurityBaseline = "v2.0"
    ComplianceScope  = "CIS-SOC2"
  })
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
# ─── KMS KEY: Data Bucket ─────────────────────────────────────────────────────
# resource "aws_kms_key" "data_bucket" {
#   description             = "KMS CMK for ${local.bucket_name} data encryption"
#   deletion_window_in_days = 30
#   enable_key_rotation     = true
#
#   policy = jsonencode({
#     Version = "2012-10-17"
#     Id      = "key-policy-s3"
#     Statement = [
#       {
#         Sid    = "EnableRootAccess"
#         Effect = "Allow"
#         Principal = {
#           AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
#         }
#         Action   = "kms:*"
#         Resource = "*"
#       },
#       {
#         Sid    = "AllowS3ServiceUse"
#         Effect = "Allow"
#         Principal = { Service = "s3.amazonaws.com" }
#         Action   = ["kms:GenerateDataKey*", "kms:Decrypt"]
#         Resource = "*"
#       },
#       {
#         Sid    = "AllowCloudTrailEncrypt"
#         Effect = "Allow"
#         Principal = { Service = "cloudtrail.amazonaws.com" }
#         Action   = ["kms:GenerateDataKey*", "kms:DescribeKey"]
#         Resource = "*"
#       }
#     ]
#   })
#
#   tags = merge(local.common_tags, { Name = "${local.bucket_name}-key" })
# }
#
# resource "aws_kms_alias" "data_bucket" {
#   name          = "alias/${local.bucket_name}-key"
#   target_key_id = aws_kms_key.data_bucket.key_id
# }

# ─── KMS KEY: Log Bucket ──────────────────────────────────────────────────────
# resource "aws_kms_key" "log_bucket" {
#   description             = "KMS CMK for ${local.log_bucket_name} log encryption"
#   deletion_window_in_days = 30
#   enable_key_rotation     = true
#   tags                    = merge(local.common_tags, { Name = "${local.log_bucket_name}-key" })
# }
#
# resource "aws_kms_alias" "log_bucket" {
#   name          = "alias/${local.log_bucket_name}-key"
#   target_key_id = aws_kms_key.log_bucket.key_id
# }

# ─── S3 LOGGING BUCKET ────────────────────────────────────────────────────────
resource "aws_s3_bucket" "logs" {
  bucket        = local.log_bucket_name
  force_destroy = false
  tags          = merge(local.common_tags, { Name = local.log_bucket_name, Purpose = "SecurityLogs" })
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    id     = "log-lifecycle"
    status = "Enabled"

    filter {}

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 180
      storage_class = "GLACIER"
    }

    expiration {
      days = var.log_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

resource "aws_s3_bucket_policy" "logs" {
  bucket = aws_s3_bucket.logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "LogBucketPolicy"
    Statement = [
      {
        Sid       = "AllowS3LogDelivery"
        Effect    = "Allow"
        Principal = { Service = "logging.s3.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.logs.arn}/s3-access-logs/*"
        Condition = {
          ArnLike      = { "aws:SourceArn" = aws_s3_bucket.data.arn }
          StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        }
      },
      {
        Sid       = "AllowCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource = "${aws_s3_bucket.logs.arn}/cloudtrail/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      {
        Sid       = "AllowCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.logs.arn
      },
      {
        Sid       = "DenyHTTP"
        Effect    = "Deny"
        Principal = { AWS = "*" }
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.logs.arn, "${aws_s3_bucket.logs.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "DenyDeleteLogs"
        Effect    = "Deny"
        Principal = { AWS = "*" }
        Action    = ["s3:DeleteObject", "s3:DeleteObjectVersion", "s3:DeleteBucket"]
        Resource  = [aws_s3_bucket.logs.arn, "${aws_s3_bucket.logs.arn}/*"]
        Condition = {
          StringNotEquals = { "aws:PrincipalArn" = var.log_admin_role_arn }
        }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.logs]
}

# ─── S3 DATA BUCKET ───────────────────────────────────────────────────────────
resource "aws_s3_bucket" "data" {
  bucket        = local.bucket_name
  force_destroy = false

  tags = merge(local.common_tags, {
    Name               = local.bucket_name
    DataClassification = var.data_classification
  })
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "data" {
  bucket = aws_s3_bucket.data.id
  rule { object_ownership = "BucketOwnerEnforced" }
  depends_on = [aws_s3_bucket_public_access_block.data]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status     = "Enabled"
    mfa_delete = var.enable_mfa_delete ? "Enabled" : "Disabled"
  }
}

resource "aws_s3_bucket_logging" "data" {
  bucket        = aws_s3_bucket.data.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "s3-access-logs/${local.bucket_name}/"
  depends_on    = [aws_s3_bucket_policy.logs]
}

resource "aws_s3_bucket_lifecycle_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    id     = "transition-old-versions"
    status = "Enabled"
    filter {}
    noncurrent_version_transition {
      noncurrent_days = 30
      storage_class   = "STANDARD_IA"
    }
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
  rule {
    id     = "abort-multipart"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
  depends_on = [aws_s3_bucket_versioning.data]
}

resource "aws_s3_bucket_policy" "data" {
  bucket = aws_s3_bucket.data.id

  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "SecureDataBucketPolicy"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = { AWS = "*" }
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.data.arn, "${aws_s3_bucket.data.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      #{
      #Sid       = "DenyUnencryptedUploads"
      #Effect    = "Deny"
      #Principal = { AWS = "*" }
      #Action    = "s3:PutObject"
      #Resource  = "${aws_s3_bucket.data.arn}/*"
      #Condition = {
      #Null = { "s3:x-amz-server-side-encryption-aws-kms-key-id" = "true" }
      #}
      #},
      #{
      #Sid       = "DenyWrongKMSKey"
      #Effect    = "Deny"
      #Principal = { AWS = "*" }
      #Action    = "s3:PutObject"
      #Resource  = "${aws_s3_bucket.data.arn}/*"
      #Condition = {
      #StringNotEqualsIfExists = {
      #"s3:x-amz-server-side-encryption-aws-kms-key-id" = aws_kms_key.data_bucket.arn
      #}
      #}
      #},
      {
        Sid       = "AllowAppRoleAccess"
        Effect    = "Allow"
        Principal = { AWS = var.allowed_role_arns }
        Action    = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"]
        Resource  = [aws_s3_bucket.data.arn, "${aws_s3_bucket.data.arn}/*"]
      }
    ]
  })

  depends_on = [
    aws_s3_bucket_public_access_block.data,
    aws_s3_bucket_ownership_controls.data
  ]
}

# ─── ACCOUNT-LEVEL PUBLIC ACCESS BLOCK ───────────────────────────────────────
resource "aws_s3_account_public_access_block" "account" {
  count                   = var.manage_account_public_access_block ? 1 : 0
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}
