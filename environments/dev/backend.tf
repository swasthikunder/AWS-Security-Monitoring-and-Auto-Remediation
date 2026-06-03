# environments/dev/backend.tf
# -----------------------------------------------------------------------------
# OPTION A: Local backend (default — use this to get started)
# -----------------------------------------------------------------------------
terraform {
  backend "local" {
    path = "terraform.tfstate"
  }
}

# -----------------------------------------------------------------------------
# OPTION B: S3 Remote Backend (recommended for teams)
# Uncomment this block and comment out Option A above
# Pre-create the S3 bucket and DynamoDB table before running terraform init
# -----------------------------------------------------------------------------

# terraform {
#   backend "s3" {
#     bucket         = "your-terraform-state-bucket"
#     key            = "aws-s3-iam-security/dev/terraform.tfstate"
#     region         = "us-east-1"
#     encrypt        = true
#     kms_key_id     = "arn:aws:kms:us-east-1:ACCOUNT_ID:key/KEY_ID"
#     dynamodb_table = "terraform-state-lock"
#   }
# }

# -----------------------------------------------------------------------------
# How to create the S3 state bucket (run once manually):
# -----------------------------------------------------------------------------
# aws s3api create-bucket \
#   --bucket your-terraform-state-bucket \
#   --region us-east-1
#
# aws s3api put-bucket-versioning \
#   --bucket your-terraform-state-bucket \
#   --versioning-configuration Status=Enabled
#
# aws s3api put-bucket-encryption \
#   --bucket your-terraform-state-bucket \
#   --server-side-encryption-configuration '{
#     "Rules": [{
#       "ApplyServerSideEncryptionByDefault": {
#         "SSEAlgorithm": "aws:kms"
#       }
#     }]
#   }'
#
# aws s3api put-public-access-block \
#   --bucket your-terraform-state-bucket \
#   --public-access-block-configuration \
#     "BlockPublicAcls=true,IgnorePublicAcls=true,\
#      BlockPublicPolicy=true,RestrictPublicBuckets=true"
#
# aws dynamodb create-table \
#   --table-name terraform-state-lock \
#   --attribute-definitions AttributeName=LockID,AttributeType=S \
#   --key-schema AttributeName=LockID,KeyType=HASH \
#   --billing-mode PAY_PER_REQUEST \
#   --region us-east-1