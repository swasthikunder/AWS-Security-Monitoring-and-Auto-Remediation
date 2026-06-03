#!/usr/bin/env bash
# validate-controls.sh
# Quick AWS S3 & IAM security control validation.
# Usage: ./scripts/validate-controls.sh [--bucket BUCKET_NAME]
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0

pass()  { echo -e "${GREEN}✅ PASS${NC} $1"; ((PASS++)); }
fail()  { echo -e "${RED}❌ FAIL${NC} $1"; ((FAIL++)); }
warn()  { echo -e "${YELLOW}⚠️  WARN${NC} $1"; ((WARN++)); }
header(){ echo -e "\n${YELLOW}=== $1 ===${NC}"; }

# ── Parse args ────────────────────────────────────────────────────────────────
TARGET_BUCKET=""
while [[ $# -gt 0 ]]; do
  case $1 in
    --bucket) TARGET_BUCKET="$2"; shift 2 ;;
    *) shift ;;
  esac
done

echo "======================================================"
echo "  AWS S3 & IAM Security Control Validation"
echo "  $(date)"
echo "======================================================"

# ── Verify AWS auth ────────────────────────────────────────────────────────────
IDENTITY=$(aws sts get-caller-identity --output json 2>/dev/null) || {
  echo "ERROR: AWS credentials not configured. Run 'aws configure'."
  exit 1
}
ACCOUNT_ID=$(echo "$IDENTITY" | python3 -c "import sys,json; print(json.load(sys.stdin)['Account'])")
echo "Account: $ACCOUNT_ID"
echo "Caller:  $(echo "$IDENTITY" | python3 -c "import sys,json; print(json.load(sys.stdin)['Arn'])")"

# ─────────────────────────────────────────────────────────────────────────────
header "1. ACCOUNT-LEVEL S3 CONTROLS"
# ─────────────────────────────────────────────────────────────────────────────
BPA=$(aws s3control get-public-access-block --account-id "$ACCOUNT_ID" --output json 2>/dev/null || echo '{}')
BLOCK_ACLS=$(echo "$BPA"   | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('PublicAccessBlockConfiguration',{}).get('BlockPublicAcls', False))" 2>/dev/null || echo "false")
BLOCK_POLICY=$(echo "$BPA" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('PublicAccessBlockConfiguration',{}).get('BlockPublicPolicy', False))" 2>/dev/null || echo "false")
RESTRICT=$(echo "$BPA"     | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('PublicAccessBlockConfiguration',{}).get('RestrictPublicBuckets', False))" 2>/dev/null || echo "false")

[[ "$BLOCK_ACLS" == "True" ]]   && pass "BlockPublicAcls enabled at account level"   || fail "BlockPublicAcls NOT enabled at account level"
[[ "$BLOCK_POLICY" == "True" ]] && pass "BlockPublicPolicy enabled at account level"  || fail "BlockPublicPolicy NOT enabled at account level"
[[ "$RESTRICT" == "True" ]]     && pass "RestrictPublicBuckets enabled at account level" || fail "RestrictPublicBuckets NOT enabled at account level"

# ─────────────────────────────────────────────────────────────────────────────
header "2. IAM ROOT ACCOUNT CHECKS"
# ─────────────────────────────────────────────────────────────────────────────
SUMMARY=$(aws iam get-account-summary --output json)
ROOT_KEYS=$(echo "$SUMMARY" | python3 -c "import sys,json; print(json.load(sys.stdin)['SummaryMap'].get('AccountAccessKeysPresent', 1))")
ROOT_MFA=$(echo "$SUMMARY"  | python3 -c "import sys,json; print(json.load(sys.stdin)['SummaryMap'].get('AccountMFAEnabled', 0))")

[[ "$ROOT_KEYS" == "0" ]] && pass "Root account has no access keys" || fail "Root account has $ROOT_KEYS access key(s) — CRITICAL"
[[ "$ROOT_MFA"  == "1" ]] && pass "Root account MFA is enabled"    || fail "Root account MFA is NOT enabled — CRITICAL"

# ─────────────────────────────────────────────────────────────────────────────
header "3. IAM PASSWORD POLICY"
# ─────────────────────────────────────────────────────────────────────────────
PP=$(aws iam get-account-password-policy --output json 2>/dev/null || echo '{}')
MIN_LEN=$(echo "$PP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('PasswordPolicy',{}).get('MinimumPasswordLength', 0))" 2>/dev/null || echo "0")
[[ "$MIN_LEN" -ge 14 ]] && pass "Password min length $MIN_LEN >= 14" || fail "Password min length $MIN_LEN < 14"

# ─────────────────────────────────────────────────────────────────────────────
header "4. GUARDDUTY"
# ─────────────────────────────────────────────────────────────────────────────
DETECTORS=$(aws guardduty list-detectors --output json | python3 -c "import sys,json; ids=json.load(sys.stdin).get('DetectorIds',[]); print(' '.join(ids))")
if [[ -z "$DETECTORS" ]]; then
  fail "GuardDuty is NOT enabled"
else
  pass "GuardDuty detector(s) found: $DETECTORS"
  for DID in $DETECTORS; do
    GD=$(aws guardduty get-detector --detector-id "$DID" --output json)
    STATUS=$(echo "$GD" | python3 -c "import sys,json; print(json.load(sys.stdin).get('Status','DISABLED'))")
    S3P=$(echo "$GD"    | python3 -c "import sys,json; print(json.load(sys.stdin).get('DataSources',{}).get('S3Logs',{}).get('Status','DISABLED'))")
    [[ "$STATUS" == "ENABLED" ]] && pass "GuardDuty status: ENABLED"    || fail "GuardDuty status: $STATUS"
    [[ "$S3P"    == "ENABLED" ]] && pass "GuardDuty S3 Protection: ENABLED" || fail "GuardDuty S3 Protection: $S3P"
  done
fi

# ─────────────────────────────────────────────────────────────────────────────
header "5. CLOUDTRAIL"
# ─────────────────────────────────────────────────────────────────────────────
TRAILS=$(aws cloudtrail describe-trails --include-shadow-trails false --output json)
TRAIL_COUNT=$(echo "$TRAILS" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('trailList',[])))")
[[ "$TRAIL_COUNT" -gt 0 ]] && pass "CloudTrail: $TRAIL_COUNT trail(s) configured" || fail "No CloudTrail trails found"

echo "$TRAILS" | python3 -c "
import sys, json, subprocess
trails = json.load(sys.stdin).get('trailList', [])
for t in trails:
    name = t.get('Name','')
    multi = t.get('IsMultiRegionTrail', False)
    validation = t.get('LogFileValidationEnabled', False)
    if multi:
        print(f'  MULTI_REGION trail: {name}')
    if not validation:
        print(f'  WARN: LogFileValidation DISABLED on {name}')
"

# ─────────────────────────────────────────────────────────────────────────────
header "6. IAM ACCESS ANALYZER"
# ─────────────────────────────────────────────────────────────────────────────
ANALYZERS=$(aws accessanalyzer list-analyzers --output json | python3 -c "
import sys,json
analyzers = json.load(sys.stdin).get('analyzers', [])
active = [a for a in analyzers if a.get('status') == 'ACTIVE']
print(len(active))
")
[[ "$ANALYZERS" -gt 0 ]] && pass "IAM Access Analyzer: $ANALYZERS active analyzer(s)" || fail "No active IAM Access Analyzer found"

# ─────────────────────────────────────────────────────────────────────────────
header "7. PER-BUCKET CHECKS"
# ─────────────────────────────────────────────────────────────────────────────
BUCKETS=""
if [[ -n "$TARGET_BUCKET" ]]; then
  BUCKETS="$TARGET_BUCKET"
else
  BUCKETS=$(aws s3api list-buckets --output json | python3 -c "
import sys,json
buckets = json.load(sys.stdin).get('Buckets',[])
print(' '.join(b['Name'] for b in buckets))
")
fi

for BUCKET in $BUCKETS; do
  echo ""
  echo "  Bucket: $BUCKET"

  # Block Public Access
  BPAB=$(aws s3api get-public-access-block --bucket "$BUCKET" --output json 2>/dev/null || echo '{}')
  BLK=$(echo "$BPAB" | python3 -c "import sys,json; c=json.load(sys.stdin).get('PublicAccessBlockConfiguration',{}); print(all(c.values()) if c else False)" 2>/dev/null || echo "False")
  [[ "$BLK" == "True" ]] && pass "    Block Public Access: fully enabled" || fail "    Block Public Access: NOT fully enabled"

  # Encryption
  ENC=$(aws s3api get-bucket-encryption --bucket "$BUCKET" --output json 2>/dev/null || echo '{}')
  SSE=$(echo "$ENC" | python3 -c "
import sys,json
rules = json.load(sys.stdin).get('ServerSideEncryptionConfiguration',{}).get('Rules',[])
if rules: print(rules[0].get('ApplyServerSideEncryptionByDefault',{}).get('SSEAlgorithm','none'))
else: print('none')
" 2>/dev/null || echo "none")
  [[ "$SSE" == "aws:kms" ]] && pass "    Encryption: SSE-KMS" || { [[ "$SSE" == "AES256" ]] && warn "    Encryption: SSE-S3 (prefer SSE-KMS)" || fail "    Encryption: DISABLED"; }

  # Versioning
  VER=$(aws s3api get-bucket-versioning --bucket "$BUCKET" --output json 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('Status','Disabled'))" 2>/dev/null || echo "Disabled")
  [[ "$VER" == "Enabled" ]] && pass "    Versioning: Enabled" || warn "    Versioning: $VER"

  # Access Logging
  LOG=$(aws s3api get-bucket-logging --bucket "$BUCKET" --output json 2>/dev/null | python3 -c "
import sys,json
d = json.load(sys.stdin)
print('Enabled' if d.get('LoggingEnabled') else 'Disabled')
" 2>/dev/null || echo "Disabled")
  [[ "$LOG" == "Enabled" ]] && pass "    Access Logging: Enabled" || warn "    Access Logging: Disabled"
done

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "======================================================"
echo "  RESULTS: PASS=$PASS  FAIL=$FAIL  WARN=$WARN"
echo "======================================================"

[[ "$FAIL" -gt 0 ]] && exit 1 || exit 0
