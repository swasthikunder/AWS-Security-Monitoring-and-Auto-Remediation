#!/usr/bin/env bash
# security-audit.sh
# Comprehensive AWS security audit – outputs JSON report.
# Usage: ./scripts/security-audit.sh [--output FILE] [--region REGION]
set -euo pipefail

OUTPUT_FILE="security-audit-$(date +%Y%m%d-%H%M%S).json"
AWS_REGION="${AWS_DEFAULT_REGION:-us-east-1}"

while [[ $# -gt 0 ]]; do
  case $1 in
    --output) OUTPUT_FILE="$2"; shift 2 ;;
    --region) AWS_REGION="$2";  shift 2 ;;
    *) shift ;;
  esac
done

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)

echo "Starting security audit for account $ACCOUNT_ID in $AWS_REGION..."

python3 - <<PYEOF
import json, boto3, sys
from datetime import datetime, timezone

session  = boto3.Session(region_name="$AWS_REGION")
s3       = session.client("s3")
iam      = session.client("iam")
gd       = session.client("guardduty")
ct       = session.client("cloudtrail")
aa       = session.client("accessanalyzer")
s3ctrl   = session.client("s3control")
config   = session.client("config")

findings = []

def check(name, passed, detail, severity="MEDIUM", remediation=""):
    status = "PASS" if passed else "FAIL"
    color  = "✅" if passed else "❌"
    print(f"  {color} [{severity}] {name}: {detail}")
    findings.append({
        "check": name, "status": status, "detail": detail,
        "severity": severity, "remediation": remediation
    })
    return passed

# ── Account checks ─────────────────────────────────────────────────────────
print("\n[Account-Level Checks]")
acct = "$ACCOUNT_ID"
try:
    bpa = s3ctrl.get_public_access_block(AccountId=acct)["PublicAccessBlockConfiguration"]
    all_on = all(bpa.values())
    check("Account S3 Block Public Access", all_on,
          "All 4 settings enabled" if all_on else f"Settings: {bpa}",
          "CRITICAL", "Enable all Block Public Access settings at account level")
except Exception as e:
    check("Account S3 Block Public Access", False, f"Error: {e}", "CRITICAL")

summary = iam.get_account_summary()["SummaryMap"]
check("Root No Access Keys", summary.get("AccountAccessKeysPresent", 1) == 0,
      "No root access keys" if summary.get("AccountAccessKeysPresent",1)==0 else f"{summary.get('AccountAccessKeysPresent')} keys exist",
      "CRITICAL", "Delete root access keys immediately")
check("Root MFA Enabled", bool(summary.get("AccountMFAEnabled", 0)),
      "MFA enabled" if summary.get("AccountMFAEnabled") else "MFA NOT enabled",
      "CRITICAL", "Enable MFA on root account")

# ── S3 bucket checks ───────────────────────────────────────────────────────
print("\n[S3 Bucket Checks]")
buckets = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
print(f"  Scanning {len(buckets)} bucket(s)...")

for b in buckets:
    try:
        bpa = s3.get_public_access_block(Bucket=b)["PublicAccessBlockConfiguration"]
        check(f"S3 Block Public Access: {b}", all(bpa.values()),
              "Enabled" if all(bpa.values()) else str(bpa), "HIGH")
    except Exception:
        check(f"S3 Block Public Access: {b}", False, "Not configured", "HIGH")

    try:
        enc = s3.get_bucket_encryption(Bucket=b)
        algo = enc["ServerSideEncryptionConfiguration"]["Rules"][0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
        check(f"S3 Encryption: {b}", algo in ("aws:kms","AES256"),
              f"Algorithm: {algo}", "HIGH" if algo!="aws:kms" else "LOW")
    except Exception:
        check(f"S3 Encryption: {b}", False, "No encryption configured", "HIGH")

    try:
        ver = s3.get_bucket_versioning(Bucket=b).get("Status","Disabled")
        check(f"S3 Versioning: {b}", ver=="Enabled", f"Status: {ver}", "MEDIUM")
    except Exception:
        check(f"S3 Versioning: {b}", False, "Error checking versioning", "MEDIUM")

# ── GuardDuty ─────────────────────────────────────────────────────────────
print("\n[GuardDuty]")
try:
    detectors = gd.list_detectors()["DetectorIds"]
    if detectors:
        det = gd.get_detector(DetectorId=detectors[0])
        check("GuardDuty Enabled", det["Status"]=="ENABLED", det["Status"], "CRITICAL")
        s3p = det.get("DataSources",{}).get("S3Logs",{}).get("Status","DISABLED")
        check("GuardDuty S3 Protection", s3p=="ENABLED", s3p, "HIGH")
    else:
        check("GuardDuty Enabled", False, "No detectors found", "CRITICAL")
except Exception as e:
    check("GuardDuty", False, str(e), "CRITICAL")

# ── CloudTrail ────────────────────────────────────────────────────────────
print("\n[CloudTrail]")
try:
    trails = ct.describe_trails(includeShadowTrails=False)["trailList"]
    check("CloudTrail Configured", len(trails)>0, f"{len(trails)} trail(s)", "CRITICAL")
    for t in trails:
        check(f"Log Validation: {t['Name']}", t.get("LogFileValidationEnabled",False),
              "Enabled" if t.get("LogFileValidationEnabled") else "DISABLED", "HIGH")
        check(f"Multi-Region: {t['Name']}", t.get("IsMultiRegionTrail",False),
              "Yes" if t.get("IsMultiRegionTrail") else "No", "MEDIUM")
except Exception as e:
    check("CloudTrail", False, str(e), "CRITICAL")

# ── IAM Access Analyzer ───────────────────────────────────────────────────
print("\n[IAM Access Analyzer]")
try:
    analyzers = [a for a in aa.list_analyzers()["analyzers"] if a["status"]=="ACTIVE"]
    check("Access Analyzer Active", len(analyzers)>0, f"{len(analyzers)} active", "HIGH")
    for a in analyzers:
        findings_resp = aa.list_findings(
            analyzerArn=a["arn"],
            filter={"status": {"eq": ["ACTIVE"]}, "isPublic": {"eq": ["true"]}}
        )
        public_count = len(findings_resp.get("findings",[]))
        check(f"No Public Findings: {a['name']}", public_count==0,
              f"{public_count} public finding(s)", "CRITICAL" if public_count>0 else "LOW")
except Exception as e:
    check("Access Analyzer", False, str(e), "HIGH")

# ── Summary ────────────────────────────────────────────────────────────────
total  = len(findings)
passed = sum(1 for f in findings if f["status"]=="PASS")
failed = sum(1 for f in findings if f["status"]=="FAIL")
score  = round(passed / total * 100, 1) if total > 0 else 0

report = {
    "generated_at": "$TIMESTAMP",
    "account_id":   "$ACCOUNT_ID",
    "region":       "$AWS_REGION",
    "summary": {"total": total, "passed": passed, "failed": failed, "score_pct": score},
    "findings": findings
}

with open("$OUTPUT_FILE", "w") as f:
    json.dump(report, f, indent=2)

print(f"\n{'='*50}")
print(f"AUDIT COMPLETE: {passed}/{total} checks passed ({score}%)")
print(f"Report saved to: $OUTPUT_FILE")
print(f"{'='*50}")

sys.exit(0 if failed == 0 else 1)
PYEOF
