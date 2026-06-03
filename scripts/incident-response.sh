#!/usr/bin/env bash
# incident-response.sh
# AWS S3 & IAM Incident Response Automation
#
# Usage:
#   ./scripts/incident-response.sh lock-bucket <bucket-name>
#   ./scripts/incident-response.sh rotate-key <username> <access-key-id>
#   ./scripts/incident-response.sh audit-bucket <bucket-name>
#   ./scripts/incident-response.sh disable-user <username>
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

_log()  { echo -e "[$(date -u +%H:%M:%S)] $*"; }
_ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
_err()  { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# ─────────────────────────────────────────────────────────────────────────────
lock_bucket() {
  local BUCKET="${1:-}"
  [[ -z "$BUCKET" ]] && _err "Usage: $0 lock-bucket <bucket-name>"

  _log "🔒 Locking down S3 bucket: $BUCKET"
  _log "Account: $ACCOUNT_ID"

  # Step 1: Enable Block Public Access
  _log "Step 1: Enabling Block Public Access..."
  aws s3api put-public-access-block --bucket "$BUCKET" \
    --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
  _ok "Block Public Access enabled"

  # Step 2: Reset ACL to private
  _log "Step 2: Resetting ACL to private..."
  aws s3api put-bucket-acl --bucket "$BUCKET" --acl private 2>/dev/null && _ok "ACL reset to private" || _warn "Could not reset ACL (may already be disabled)"

  # Step 3: Check and remove public policy statements
  _log "Step 3: Checking bucket policy for public statements..."
  POLICY=$(aws s3api get-bucket-policy --bucket "$BUCKET" --output text 2>/dev/null || echo "")
  if [[ -n "$POLICY" ]]; then
    _warn "Bucket policy exists. Review manually:"
    echo "$POLICY" | python3 -c "import sys,json; print(json.dumps(json.load(sys.stdin), indent=2))"
    read -rp "Delete entire policy? [y/N] " confirm
    if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
      aws s3api delete-bucket-policy --bucket "$BUCKET"
      _ok "Bucket policy deleted"
    fi
  else
    _ok "No bucket policy found"
  fi

  # Step 4: Verify
  _log "Step 4: Verifying controls..."
  BPA=$(aws s3api get-public-access-block --bucket "$BUCKET" --output json)
  echo "$BPA" | python3 -c "import sys,json; c=json.load(sys.stdin)['PublicAccessBlockConfiguration']; print('  ' + ('ALL BLOCKED ✅' if all(c.values()) else 'INCOMPLETE ❌') + f': {c}')"

  _log ""
  _ok "Bucket $BUCKET locked. Next steps:"
  echo "  1. Review CloudTrail: was any sensitive data accessed or downloaded?"
  echo "     aws cloudtrail lookup-events --lookup-attributes AttributeKey=ResourceName,AttributeValue=$BUCKET"
  echo "  2. Check S3 access logs for the bucket."
  echo "  3. If data was exfiltrated, notify your DPO/compliance team within 72h (GDPR/HIPAA)."
  echo "  4. Identify root cause (misconfigured Terraform, manual change, etc.) and patch."
}

# ─────────────────────────────────────────────────────────────────────────────
rotate_key() {
  local USERNAME="${1:-}"
  local KEY_ID="${2:-}"
  [[ -z "$USERNAME" || -z "$KEY_ID" ]] && _err "Usage: $0 rotate-key <username> <access-key-id>"

  _log "🔄 Rotating IAM credentials for user: $USERNAME (key: $KEY_ID)"

  # Step 1: Disable the compromised key immediately
  _log "Step 1: Disabling access key $KEY_ID..."
  aws iam update-access-key --user-name "$USERNAME" --access-key-id "$KEY_ID" --status Inactive
  _ok "Key $KEY_ID disabled"

  # Step 2: Create a new key
  _log "Step 2: Creating new access key..."
  NEW_KEY=$(aws iam create-access-key --user-name "$USERNAME" --output json)
  NEW_KEY_ID=$(echo "$NEW_KEY" | python3 -c "import sys,json; print(json.load(sys.stdin)['AccessKey']['AccessKeyId'])")
  NEW_SECRET=$(echo "$NEW_KEY"  | python3 -c "import sys,json; print(json.load(sys.stdin)['AccessKey']['SecretAccessKey'])")

  _ok "New key created: $NEW_KEY_ID"
  echo ""
  echo "  ⚠️  SAVE THESE CREDENTIALS NOW — they will not be shown again:"
  echo "  AccessKeyId:     $NEW_KEY_ID"
  echo "  SecretAccessKey: $NEW_SECRET"
  echo ""

  # Step 3: Advise on deleting the old key after confirming new one works
  _warn "The old key ($KEY_ID) is now Inactive (not yet deleted)."
  read -rp "Delete the old key now? [y/N] " confirm
  if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
    aws iam delete-access-key --user-name "$USERNAME" --access-key-id "$KEY_ID"
    _ok "Old key $KEY_ID permanently deleted"
  else
    _warn "Old key kept as Inactive. Delete it once new key is confirmed working:"
    echo "  aws iam delete-access-key --user-name $USERNAME --access-key-id $KEY_ID"
  fi

  _log ""
  _ok "Credential rotation complete. Next steps:"
  echo "  1. Update all services/apps using the old key."
  echo "  2. Search code repositories for the old key ID."
  echo "  3. Review CloudTrail for actions taken with the compromised key:"
  echo "     aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=$USERNAME"
}

# ─────────────────────────────────────────────────────────────────────────────
audit_bucket() {
  local BUCKET="${1:-}"
  [[ -z "$BUCKET" ]] && _err "Usage: $0 audit-bucket <bucket-name>"

  _log "🔍 Auditing S3 bucket: $BUCKET"
  echo ""

  echo "── Block Public Access ────────────────────────────────"
  aws s3api get-public-access-block --bucket "$BUCKET" --output json 2>/dev/null \
    | python3 -c "import sys,json; c=json.load(sys.stdin).get('PublicAccessBlockConfiguration',{}); [print(f'  {k}: {v}') for k,v in c.items()]" \
    || echo "  NOT CONFIGURED"

  echo ""
  echo "── Encryption ─────────────────────────────────────────"
  aws s3api get-bucket-encryption --bucket "$BUCKET" --output json 2>/dev/null \
    | python3 -c "
import sys,json
r = json.load(sys.stdin).get('ServerSideEncryptionConfiguration',{}).get('Rules',[])
for rule in r:
    d = rule.get('ApplyServerSideEncryptionByDefault',{})
    print(f'  Algorithm: {d.get(\"SSEAlgorithm\",\"none\")}')
    print(f'  KMS Key:   {d.get(\"KMSMasterKeyID\",\"default\")}')
" || echo "  NOT ENABLED"

  echo ""
  echo "── Versioning ─────────────────────────────────────────"
  aws s3api get-bucket-versioning --bucket "$BUCKET" --output json \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'  Status: {d.get(\"Status\",\"Disabled\")}')"

  echo ""
  echo "── Access Logging ─────────────────────────────────────"
  aws s3api get-bucket-logging --bucket "$BUCKET" --output json \
    | python3 -c "
import sys,json
d = json.load(sys.stdin).get('LoggingEnabled',{})
if d:
    print(f'  Target: {d.get(\"TargetBucket\",\"?\")}')
    print(f'  Prefix: {d.get(\"TargetPrefix\",\"?\")}')
else:
    print('  DISABLED')
"

  echo ""
  echo "── Bucket Policy ──────────────────────────────────────"
  POLICY=$(aws s3api get-bucket-policy --bucket "$BUCKET" --output text 2>/dev/null || echo "")
  if [[ -n "$POLICY" ]]; then
    echo "$POLICY" | python3 -c "import sys,json; print(json.dumps(json.load(sys.stdin), indent=2))"
  else
    echo "  No bucket policy"
  fi

  echo ""
  _ok "Audit complete for $BUCKET"
}

# ─────────────────────────────────────────────────────────────────────────────
disable_user() {
  local USERNAME="${1:-}"
  [[ -z "$USERNAME" ]] && _err "Usage: $0 disable-user <username>"

  _log "⛔ Disabling IAM user: $USERNAME"

  # Disable all access keys
  KEYS=$(aws iam list-access-keys --user-name "$USERNAME" --output json \
    | python3 -c "import sys,json; [print(k['AccessKeyId']) for k in json.load(sys.stdin)['AccessKeyMetadata'] if k['Status']=='Active']")

  for KEY in $KEYS; do
    aws iam update-access-key --user-name "$USERNAME" --access-key-id "$KEY" --status Inactive
    _ok "Disabled key: $KEY"
  done

  # Deactivate console login
  aws iam delete-login-profile --user-name "$USERNAME" 2>/dev/null && _ok "Console login disabled" || _warn "No console login found"

  _ok "User $USERNAME disabled. Keys made Inactive, console login removed."
  echo "  To re-enable: aws iam create-login-profile --user-name $USERNAME --password <NEW_PASS>"
}

# ─────────────────────────────────────────────────────────────────────────────
COMMAND="${1:-}"
shift || true

case "$COMMAND" in
  lock-bucket)   lock_bucket "$@" ;;
  rotate-key)    rotate_key "$@" ;;
  audit-bucket)  audit_bucket "$@" ;;
  disable-user)  disable_user "$@" ;;
  *)
    echo "AWS S3 & IAM Incident Response Tool"
    echo ""
    echo "Usage: $0 <command> [args]"
    echo ""
    echo "Commands:"
    echo "  lock-bucket  <bucket>             Block all public access + reset ACL + clean policy"
    echo "  rotate-key   <username> <key-id>  Disable key, issue new one"
    echo "  audit-bucket <bucket>             Print full security posture of a bucket"
    echo "  disable-user <username>           Disable all keys + console login"
    exit 1
    ;;
esac
