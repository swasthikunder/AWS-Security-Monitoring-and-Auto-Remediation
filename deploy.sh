#!/usr/bin/env bash
# =============================================================================
# deploy.sh — AWS S3 & IAM Security Project Deployment Script
# =============================================================================
set -euo pipefail

# ─────────────────────────────────────────────
# Colors
# ─────────────────────────────────────────────
RED='\033[0;31m'    
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ─────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────
ENVIRONMENT="${1:-dev}"
ACTION="${2:-plan}"
WORKING_DIR="environments/${ENVIRONMENT}"
TF_VERSION_REQUIRED="1.5.0"
LOG_FILE="deploy-$(date +%Y%m%d-%H%M%S).log"

# ─────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    echo -e "${timestamp} [${level}] ${message}" | tee -a "$LOG_FILE"
}

info()    { log "INFO " "${BLUE}$*${NC}"; }
success() { log "OK   " "${GREEN}✅ $*${NC}"; }
warn()    { log "WARN " "${YELLOW}⚠️  $*${NC}"; }
error()   { log "ERROR" "${RED}❌ $*${NC}"; }
header()  { echo -e "\n${CYAN}════════════════════════════════════════${NC}"; \
            echo -e "${CYAN}  $*${NC}"; \
            echo -e "${CYAN}════════════════════════════════════════${NC}\n"; }

# ─────────────────────────────────────────────
# Usage
# ─────────────────────────────────────────────
usage() {
    cat <<EOF
Usage: $0 [ENVIRONMENT] [ACTION]

ENVIRONMENT:
  dev       (default)
  staging
  prod

ACTION:
  plan      Run terraform plan only (default)
  apply     Run terraform apply
  destroy   Run terraform destroy
  validate  Run terraform validate + security scans
  audit     Run post-deploy security audit

Examples:
  $0 dev plan
  $0 dev apply
  $0 dev validate
  $0 prod plan
  $0 dev audit
EOF
}

# ─────────────────────────────────────────────
# Preflight Checks
# ─────────────────────────────────────────────
preflight_checks() {
    header "Preflight Checks"

    # Check Terraform installed
    if ! command -v terraform &>/dev/null; then
        error "Terraform is not installed"
        echo "Install from: https://developer.hashicorp.com/terraform/downloads"
        exit 1
    fi
    success "Terraform installed: $(terraform version -json | python3 -c 'import json,sys; print(json.load(sys.stdin)["terraform_version"])')"

    # Check Terraform version
    TF_INSTALLED=$(terraform version -json | python3 -c \
        'import json,sys; print(json.load(sys.stdin)["terraform_version"])')
    if ! python3 -c "
from packaging.version import Version
installed = Version('$TF_INSTALLED')
required  = Version('$TF_VERSION_REQUIRED')
exit(0 if installed >= required else 1)
" 2>/dev/null; then
        warn "Terraform version $TF_INSTALLED may be below required $TF_VERSION_REQUIRED"
    fi

    # Check AWS CLI installed
    if ! command -v aws &>/dev/null; then
        error "AWS CLI is not installed"
        echo "Install from: https://aws.amazon.com/cli/"
        exit 1
    fi
    success "AWS CLI installed: $(aws --version 2>&1 | awk '{print $1}')"

    # Check AWS credentials configured
    if ! aws sts get-caller-identity &>/dev/null; then
        error "AWS credentials not configured or invalid"
        echo "Run: aws configure  OR  export AWS_PROFILE=your-profile"
        exit 1
    fi

    # Show current identity
    IDENTITY=$(aws sts get-caller-identity --output json)
    ACCOUNT=$(echo "$IDENTITY" | python3 -c "import json,sys; print(json.load(sys.stdin)['Account'])")
    USER=$(echo "$IDENTITY" | python3 -c "import json,sys; print(json.load(sys.stdin)['Arn'])")
    success "AWS Identity: $USER"
    info    "AWS Account:  $ACCOUNT"

    # Check working directory exists
    if [ ! -d "$WORKING_DIR" ]; then
        error "Environment directory not found: $WORKING_DIR"
        echo "Available environments:"
        ls environments/ 2>/dev/null || echo "  No environments found"
        exit 1
    fi
    success "Working directory: $WORKING_DIR"

    # Check tfvars exists
    if [ ! -f "$WORKING_DIR/terraform.tfvars" ]; then
        warn "terraform.tfvars not found in $WORKING_DIR"
        if [ -f "$WORKING_DIR/terraform.tfvars.example" ]; then
            warn "Copying terraform.tfvars.example → terraform.tfvars"
            cp "$WORKING_DIR/terraform.tfvars.example" "$WORKING_DIR/terraform.tfvars"
            warn "Please edit $WORKING_DIR/terraform.tfvars with your values before continuing"
            read -rp "Press ENTER when ready, or Ctrl+C to abort..."
        else
            error "No terraform.tfvars.example found either"
            exit 1
        fi
    fi
    success "terraform.tfvars found"

    # Production safety gate
    if [ "$ENVIRONMENT" = "prod" ]; then
        warn "You are deploying to PRODUCTION"
        read -rp "Type 'yes-deploy-prod' to confirm: " CONFIRM
        if [ "$CONFIRM" != "yes-deploy-prod" ]; then
            error "Production deployment aborted"
            exit 1
        fi
    fi

    success "All preflight checks passed"
}

# ─────────────────────────────────────────────
# Security Scan (pre-deploy)
# ─────────────────────────────────────────────
security_scan() {
    header "Pre-Deploy Security Scan"

    # tfsec
    if command -v tfsec &>/dev/null; then
        info "Running tfsec..."
        if tfsec . --minimum-severity HIGH 2>&1 | tee -a "$LOG_FILE"; then
            success "tfsec passed"
        else
            error "tfsec found HIGH/CRITICAL issues"
            read -rp "Continue anyway? (yes/no): " CONTINUE
            [ "$CONTINUE" = "yes" ] || exit 1
        fi
    else
        warn "tfsec not installed — skipping (install: brew install tfsec)"
    fi

    # Checkov
    if command -v checkov &>/dev/null; then
        info "Running checkov..."
        if checkov -d . --framework terraform --quiet 2>&1 | tee -a "$LOG_FILE"; then
            success "checkov passed"
        else
            warn "checkov found issues — review above"
        fi
    else
        warn "checkov not installed — skipping (install: pip install checkov)"
    fi

    # Check for hardcoded credentials
    info "Scanning for hardcoded credentials..."
    if grep -rE \
        "(AKIA[A-Z0-9]{16}|aws_secret_access_key\s*=\s*['\"][^'\"]+|password\s*=\s*['\"][^'\"]+)" \
        --include="*.tf" --include="*.json" --include="*.py" \
        --exclude-dir=".git" \
        . 2>/dev/null; then
        error "Potential hardcoded credentials found! Review above matches."
        exit 1
    else
        success "No hardcoded credentials detected"
    fi

    success "Security scan completed"
}

# ─────────────────────────────────────────────
# Terraform Operations
# ─────────────────────────────────────────────
terraform_init() {
    header "Terraform Init"
    info "Initializing Terraform in $WORKING_DIR..."

    cd "$WORKING_DIR"
    terraform init -upgrade 2>&1 | tee -a "../../$LOG_FILE"
    success "Terraform initialized"
    cd - > /dev/null
}

terraform_validate() {
    header "Terraform Validate"
    cd "$WORKING_DIR"

    info "Checking formatting..."
    if terraform fmt -check -recursive 2>&1 | tee -a "../../$LOG_FILE"; then
        success "Formatting OK"
    else
        warn "Some files need formatting — run: terraform fmt -recursive"
    fi

    info "Validating configuration..."
    terraform validate -no-color 2>&1 | tee -a "../../$LOG_FILE"
    success "Validation passed"
    cd - > /dev/null
}

terraform_plan() {
    header "Terraform Plan"
    cd "$WORKING_DIR"

    info "Generating execution plan..."
    terraform plan \
        -out=tfplan \
        -no-color \
        2>&1 | tee -a "../../$LOG_FILE"

    success "Plan generated: $WORKING_DIR/tfplan"
    echo ""
    warn "Review the plan above carefully before applying"
    cd - > /dev/null
}

terraform_apply() {
    header "Terraform Apply"
    cd "$WORKING_DIR"

    # Confirm apply
    if [ "${AUTO_APPROVE:-false}" != "true" ]; then
        echo ""
        warn "You are about to apply changes to: $ENVIRONMENT"
        read -rp "Type 'yes' to confirm apply: " CONFIRM
        if [ "$CONFIRM" != "yes" ]; then
            info "Apply aborted by user"
            exit 0
        fi
    fi

    info "Applying Terraform changes..."
    if [ -f "tfplan" ]; then
        terraform apply tfplan 2>&1 | tee -a "../../$LOG_FILE"
    else
        terraform apply -auto-approve 2>&1 | tee -a "../../$LOG_FILE"
    fi

    success "Terraform apply completed"
    cd - > /dev/null
}

terraform_destroy() {
    header "Terraform Destroy"

    error "WARNING: This will DESTROY all resources in $ENVIRONMENT"
    read -rp "Type 'destroy-$ENVIRONMENT' to confirm: " CONFIRM

    if [ "$CONFIRM" != "destroy-$ENVIRONMENT" ]; then
        info "Destroy aborted"
        exit 0
    fi

    cd "$WORKING_DIR"
    terraform destroy 2>&1 | tee -a "../../$LOG_FILE"
    success "Resources destroyed"
    cd - > /dev/null
}

# ─────────────────────────────────────────────
# Post-Deploy Audit
# ─────────────────────────────────────────────
post_deploy_audit() {
    header "Post-Deploy Security Audit"

    # Get outputs from Terraform
    cd "$WORKING_DIR"
    DATA_BUCKET=$(terraform output -raw data_bucket_name 2>/dev/null || echo "")
    LOG_BUCKET=$(terraform output -raw log_bucket_name 2>/dev/null || echo "")
    cd - > /dev/null

    if [ -z "$DATA_BUCKET" ]; then
        warn "Could not retrieve bucket names from Terraform outputs"
        read -rp "Enter data bucket name manually: " DATA_BUCKET
    fi

    info "Auditing bucket: $DATA_BUCKET"

    # Check Block Public Access
    echo ""
    info "1. Checking Block Public Access..."
    BPA=$(aws s3api get-public-access-block --bucket "$DATA_BUCKET" \
        --query 'PublicAccessBlockConfiguration' --output json 2>/dev/null || echo "{}")

    if echo "$BPA" | grep -q '"BlockPublicAcls": true'; then
        success "BlockPublicAcls = true"
    else
        error "BlockPublicAcls is NOT true"
    fi

    if echo "$BPA" | grep -q '"BlockPublicPolicy": true'; then
        success "BlockPublicPolicy = true"
    else
        error "BlockPublicPolicy is NOT true"
    fi

    # Check Encryption
    echo ""
    info "2. Checking Default Encryption..."
    ENCRYPTION=$(aws s3api get-bucket-encryption --bucket "$DATA_BUCKET" \
        --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' \
        --output text 2>/dev/null || echo "NONE")

    if [ "$ENCRYPTION" = "aws:kms" ]; then
        success "Encryption = SSE-KMS ✅"
    else
        error "Encryption = $ENCRYPTION (expected aws:kms)"
    fi

    # Check Versioning
    echo ""
    info "3. Checking Versioning..."
    VERSIONING=$(aws s3api get-bucket-versioning --bucket "$DATA_BUCKET" \
        --query 'Status' --output text 2>/dev/null || echo "None")

    if [ "$VERSIONING" = "Enabled" ]; then
        success "Versioning = Enabled ✅"
    else
        error "Versioning = $VERSIONING (expected Enabled)"
    fi

    # Check GuardDuty
    echo ""
    info "4. Checking GuardDuty..."
    DETECTOR=$(aws guardduty list-detectors --query 'DetectorIds[0]' \
        --output text 2>/dev/null || echo "None")

    if [ "$DETECTOR" != "None" ] && [ -n "$DETECTOR" ]; then
        success "GuardDuty detector found: $DETECTOR"
    else
        error "GuardDuty is NOT enabled"
    fi

    # Check Config
    echo ""
    info "5. Checking AWS Config..."
    CONFIG_RECORDERS=$(aws configservice describe-configuration-recorders \
        --query 'ConfigurationRecorders[0].name' \
        --output text 2>/dev/null || echo "None")

    if [ "$CONFIG_RECORDERS" != "None" ] && [ -n "$CONFIG_RECORDERS" ]; then
        success "AWS Config recorder: $CONFIG_RECORDERS"
    else
        warn "AWS Config recorder not found"
    fi

    # Check CloudTrail
    echo ""
    info "6. Checking CloudTrail..."
    TRAILS=$(aws cloudtrail list-trails \
        --query 'Trails[*].Name' \
        --output text 2>/dev/null || echo "None")

    if [ "$TRAILS" != "None" ] && [ -n "$TRAILS" ]; then
        success "CloudTrail trails: $TRAILS"
    else
        error "No CloudTrail trails found"
    fi

    # Check IAM Access Analyzer
    echo ""
    info "7. Checking IAM Access Analyzer..."
    ANALYZERS=$(aws accessanalyzer list-analyzers \
        --query 'analyzers[*].name' \
        --output text 2>/dev/null || echo "None")

    if [ "$ANALYZERS" != "None" ] && [ -n "$ANALYZERS" ]; then
        success "Access Analyzer: $ANALYZERS"
        # Check for active findings
        FINDINGS=$(aws accessanalyzer list-findings \
            --analyzer-arn "$(aws accessanalyzer list-analyzers \
                --query 'analyzers[0].arn' --output text)" \
            --filter '{"status": {"eq": ["ACTIVE"]}}' \
            --query 'findings | length(@)' \
            --output text 2>/dev/null || echo "0")
        if [ "$FINDINGS" -gt 0 ]; then
            warn "Access Analyzer has $FINDINGS ACTIVE findings — review immediately"
        else
            success "Access Analyzer: 0 active findings ✅"
        fi
    else
        error "IAM Access Analyzer not configured"
    fi

    # Summary
    header "Audit Summary"
    success "Post-deploy audit completed — review any ❌ items above"
    info "Full log saved to: $LOG_FILE"
}

# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────
main() {
    header "AWS S3 & IAM Security — Deploy Script"
    info "Environment : $ENVIRONMENT"
    info "Action      : $ACTION"
    info "Log file    : $LOG_FILE"

    case "$ACTION" in
        validate)
            preflight_checks
            security_scan
            terraform_init
            terraform_validate
            ;;
        plan)
            preflight_checks
            security_scan
            terraform_init
            terraform_validate
            terraform_plan
            ;;
        apply)
            preflight_checks
            security_scan
            terraform_init
            terraform_validate
            terraform_plan
            terraform_apply
            post_deploy_audit
            ;;
        destroy)
            preflight_checks
            terraform_init
            terraform_destroy
            ;;
        audit)
            preflight_checks
            post_deploy_audit
            ;;
        help|--help|-h)
            usage
            ;;
        *)
            error "Unknown action: $ACTION"
            usage
            exit 1
            ;;
    esac

    success "Done! Action '$ACTION' completed for environment '$ENVIRONMENT'"
}

main "$@"