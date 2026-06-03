"""
AWS S3 & IAM Auto-Remediation Lambda
=====================================
Triggered by:
  - EventBridge on GuardDuty HIGH/CRITICAL findings
  - AWS Config NON_COMPLIANT events
  - CloudTrail API events (PutBucketPolicy, PutBucketAcl, etc.)

Remediates:
  - S3 public access exposure (block public access, clean policies/ACLs)
  - Disabled S3 logging or encryption
  - GuardDuty S3/IAM high-severity findings
  - Account-level block public access disabled
"""

import json
import logging
import os
import traceback
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SNS_ALERT_TOPIC  = os.environ.get("SNS_ALERT_TOPIC_ARN", "")
LOG_BUCKET_NAME  = os.environ.get("LOG_BUCKET_NAME", "")
KMS_KEY_ARN      = os.environ.get("DEFAULT_KMS_KEY_ARN", "")
ACCOUNT_ID       = os.environ.get("AWS_ACCOUNT_ID", "")
DRY_RUN          = os.environ.get("DRY_RUN", "false").lower() == "true"
SLACK_WEBHOOK    = os.environ.get("SLACK_WEBHOOK_URL", "")
AUTO_DISABLE_KEYS = os.environ.get("AUTO_DISABLE_COMPROMISED_KEYS", "false").lower() == "true"

_clients: dict = {}


def get_client(service: str) -> Any:
    if service not in _clients:
        _clients[service] = boto3.client(service)
    return _clients[service]


# ─── MAIN HANDLER ─────────────────────────────────────────────────────────────
def lambda_handler(event: dict, context: Any) -> dict:
    logger.info("Remediation triggered. DRY_RUN=%s Source=%s",
                DRY_RUN, event.get("source", "unknown"))

    try:
        source      = event.get("source", "")
        detail_type = event.get("detail-type", "")
        detail      = event.get("detail", {})

        if source == "aws.guardduty":
            result = handle_guardduty_finding(detail)

        elif source == "aws.config" and "Compliance Change" in detail_type:
            result = handle_config_noncompliance(detail)

        elif source in ("aws.s3", "aws.cloudtrail"):
            result = handle_cloudtrail_event(detail)

        else:
            logger.warning("Unhandled event source: %s", source)
            result = {"action": "SKIPPED", "reason": f"Unhandled source: {source}"}

        logger.info("Result: %s", json.dumps(result, default=str))
        return {"statusCode": 200, "result": result}

    except Exception as exc:
        logger.error("Unhandled error: %s\n%s", exc, traceback.format_exc())
        _send_alert(
            title="❌ Remediation Lambda Error",
            message=f"Error: {exc}\nEvent: {json.dumps(event, default=str)[:800]}",
            severity="CRITICAL"
        )
        return {"statusCode": 500, "error": str(exc)}


# ─── GUARDDUTY HANDLER ────────────────────────────────────────────────────────
def handle_guardduty_finding(detail: dict) -> dict:
    finding      = detail.get("finding", {})
    finding_type = finding.get("type", "")
    severity     = finding.get("severity", 0)
    resource     = finding.get("resource", {})

    logger.info("GuardDuty: type=%s severity=%s", finding_type, severity)

    dispatch = {
        "Policy:S3/BucketPublicAccessGranted":          _remediate_s3_public_access,
        "Policy:S3/BucketAnonymousAccessGranted":       _remediate_s3_public_access,
        "Policy:S3/AccountBlockPublicAccessDisabled":   _remediate_account_block_public_access,
        "Stealth:S3/ServerAccessLoggingDisabled":       _remediate_s3_logging_disabled,
        "Discovery:S3/AnomalousBehavior":               _alert_only,
        "Exfiltration:S3/AnomalousBehavior":            _handle_exfiltration,
        "CredentialAccess:IAMUser/AnomalousBehavior":   _handle_iam_anomaly,
    }

    fn = None
    for pattern, func in dispatch.items():
        if finding_type.startswith(pattern):
            fn = func
            break

    action = fn(finding, resource) if fn else {"action": "ALERT_ONLY", "finding_type": finding_type}

    if severity >= 7.0:
        _send_alert(
            title=f"🚨 HIGH GuardDuty Finding: {finding_type}",
            message=(
                f"Type: {finding_type}\n"
                f"Severity: {severity}\n"
                f"Account: {finding.get('accountId', 'unknown')}\n"
                f"Action taken: {json.dumps(action, default=str)}"
            ),
            severity="HIGH"
        )

    return {"finding_type": finding_type, "severity": severity, "action": action, "dry_run": DRY_RUN}


# ─── S3 REMEDIATION FUNCTIONS ─────────────────────────────────────────────────
def _remediate_s3_public_access(finding: dict, resource: dict) -> dict:
    """Enable Block Public Access, remove public policies and ACLs."""
    bucket = _get_bucket_name(resource)
    if not bucket:
        return {"action": "SKIPPED", "reason": "Could not determine bucket name"}

    result = {"action": "BLOCK_PUBLIC_ACCESS", "bucket": bucket,
              "timestamp": _now(), "dry_run": DRY_RUN}

    if DRY_RUN:
        logger.info("[DRY RUN] Would block public access on %s", bucket)
        return result

    s3 = get_client("s3")

    # 1. Enable Block Public Access
    try:
        s3.put_public_access_block(
            Bucket=bucket,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True
            }
        )
        result["block_public_access"] = "APPLIED"
        logger.info("✅ Block Public Access enabled: %s", bucket)
    except ClientError as e:
        result["block_public_access"] = f"FAILED: {e}"

    # 2. Strip public Allow statements from bucket policy
    try:
        raw = s3.get_bucket_policy(Bucket=bucket)["Policy"]
        policy = json.loads(raw)
        cleaned = _remove_public_statements(policy)
        if cleaned["Statement"]:
            s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(cleaned))
            result["policy"] = "CLEANED"
        else:
            s3.delete_bucket_policy(Bucket=bucket)
            result["policy"] = "DELETED"
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
            result["policy"] = "NO_POLICY"
        else:
            result["policy"] = f"FAILED: {e}"

    # 3. Reset ACL to private
    try:
        s3.put_bucket_acl(Bucket=bucket, ACL="private")
        result["acl"] = "RESET_TO_PRIVATE"
    except ClientError as e:
        result["acl"] = f"FAILED: {e}"

    # 4. Tag as remediated
    try:
        existing = s3.get_bucket_tagging(Bucket=bucket).get("TagSet", [])
        tags = [t for t in existing if t["Key"] not in ("RemediatedAt", "RemediatedBy")]
        tags += [
            {"Key": "RemediatedAt", "Value": _now()},
            {"Key": "RemediatedBy", "Value": "SecurityRemediationLambda"}
        ]
        s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": tags})
    except ClientError:
        pass

    return result


def _remediate_account_block_public_access(finding: dict, resource: dict) -> dict:
    """Re-enable account-level S3 Block Public Access."""
    result = {"action": "RESTORE_ACCOUNT_BLOCK_PUBLIC_ACCESS",
              "account": ACCOUNT_ID, "timestamp": _now(), "dry_run": DRY_RUN}

    if DRY_RUN:
        logger.info("[DRY RUN] Would restore account-level block public access")
        return result

    try:
        s3control = get_client("s3control")
        s3control.put_public_access_block(
            AccountId=ACCOUNT_ID,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True
            }
        )
        result["status"] = "APPLIED"
        logger.info("✅ Account-level Block Public Access restored")
    except ClientError as e:
        result["status"] = f"FAILED: {e}"

    return result


def _remediate_s3_logging_disabled(finding: dict, resource: dict) -> dict:
    """Re-enable S3 server access logging to the configured log bucket."""
    bucket = _get_bucket_name(resource)
    if not bucket or not LOG_BUCKET_NAME:
        return {"action": "SKIPPED", "reason": "Missing bucket or LOG_BUCKET_NAME env var"}

    result = {"action": "RESTORE_LOGGING", "bucket": bucket,
              "log_bucket": LOG_BUCKET_NAME, "timestamp": _now(), "dry_run": DRY_RUN}

    if DRY_RUN:
        logger.info("[DRY RUN] Would re-enable logging on %s", bucket)
        return result

    try:
        get_client("s3").put_bucket_logging(
            Bucket=bucket,
            BucketLoggingStatus={
                "LoggingEnabled": {
                    "TargetBucket": LOG_BUCKET_NAME,
                    "TargetPrefix": f"s3-access-logs/{bucket}/"
                }
            }
        )
        result["status"] = "APPLIED"
        logger.info("✅ Logging re-enabled: %s → %s", bucket, LOG_BUCKET_NAME)
    except ClientError as e:
        result["status"] = f"FAILED: {e}"

    return result


def _remediate_s3_encryption_disabled(bucket: str) -> dict:
    """Re-enable default SSE-KMS encryption on a bucket."""
    result = {"action": "RESTORE_ENCRYPTION", "bucket": bucket,
              "timestamp": _now(), "dry_run": DRY_RUN}

    if DRY_RUN or not KMS_KEY_ARN:
        result["note"] = "DRY_RUN or no DEFAULT_KMS_KEY_ARN set"
        return result

    try:
        get_client("s3").put_bucket_encryption(
            Bucket=bucket,
            ServerSideEncryptionConfiguration={
                "Rules": [{
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "aws:kms",
                        "KMSMasterKeyID": KMS_KEY_ARN
                    },
                    "BucketKeyEnabled": True
                }]
            }
        )
        result["status"] = "APPLIED"
        logger.info("✅ Encryption restored on %s", bucket)
    except ClientError as e:
        result["status"] = f"FAILED: {e}"

    return result


def _alert_only(finding: dict, resource: dict) -> dict:
    return {
        "action": "ALERT_ONLY",
        "reason": "Anomalous behavior requires human review before automated action",
        "recommendation": "Review CloudTrail logs for this principal and consider rotating credentials."
    }


def _handle_exfiltration(finding: dict, resource: dict) -> dict:
    """Critical: potential data exfiltration. Block and alert."""
    bucket = _get_bucket_name(resource)
    _remediate_s3_public_access(finding, resource)

    _send_alert(
        title="🔴 CRITICAL: Potential S3 Data Exfiltration",
        message=(
            f"Bucket: {bucket}\n"
            f"Finding: {finding.get('type', 'unknown')}\n"
            "IMMEDIATE ACTION REQUIRED.\n"
            "1. Rotate all credentials associated with this bucket.\n"
            "2. Review CloudTrail to identify accessed objects.\n"
            "3. Notify DPO/compliance within 72h if PII/PHI involved (GDPR/HIPAA)."
        ),
        severity="CRITICAL"
    )

    return {"action": "EXFILTRATION_RESPONSE", "bucket": bucket, "public_access_blocked": True}


def _handle_iam_anomaly(finding: dict, resource: dict) -> dict:
    user       = resource.get("accessKeyDetails", {}).get("userName", "unknown")
    key_id     = resource.get("accessKeyDetails", {}).get("accessKeyId", "unknown")
    key_disabled = False

    if AUTO_DISABLE_KEYS and not DRY_RUN:
        try:
            get_client("iam").update_access_key(
                UserName=user, AccessKeyId=key_id, Status="Inactive"
            )
            key_disabled = True
            logger.warning("⚠️  Disabled key %s for user %s", key_id, user)
        except ClientError as e:
            logger.error("Failed to disable key: %s", e)

    _send_alert(
        title=f"⚠️ IAM Anomalous Behavior: {user}",
        message=(
            f"User: {user}\nKey: {key_id}\n"
            f"Key disabled: {key_disabled}\n"
            "Review CloudTrail for unauthorized actions."
        ),
        severity="HIGH"
    )

    return {"action": "IAM_ANOMALY_RESPONSE", "user": user, "key_disabled": key_disabled}


# ─── CONFIG HANDLER ───────────────────────────────────────────────────────────
def handle_config_noncompliance(detail: dict) -> dict:
    rule     = detail.get("configRuleName", "")
    resource = detail.get("resourceId", "")
    status   = detail.get("newEvaluationResult", {}).get("complianceType", "")

    if status != "NON_COMPLIANT":
        return {"action": "SKIPPED", "reason": "Not NON_COMPLIANT"}

    logger.info("Config non-compliant: rule=%s resource=%s", rule, resource)

    if "public-read" in rule or "public-write" in rule:
        return _remediate_s3_public_access({}, {"s3BucketDetails": [{"name": resource}]})
    elif "logging-enabled" in rule and "s3" in rule.lower():
        return _remediate_s3_logging_disabled({}, {"s3BucketDetails": [{"name": resource}]})
    elif "encryption-enabled" in rule and "s3" in rule.lower():
        return _remediate_s3_encryption_disabled(resource)
    else:
        _send_alert(
            title=f"⚠️ Config Non-Compliant: {rule}",
            message=f"Resource: {resource}\nRule: {rule}\nManual review required.",
            severity="MEDIUM"
        )
        return {"action": "ALERTED", "rule": rule, "resource": resource}


# ─── CLOUDTRAIL HANDLER ───────────────────────────────────────────────────────
def handle_cloudtrail_event(detail: dict) -> dict:
    event_name  = detail.get("eventName", "")
    params      = detail.get("requestParameters", {})
    bucket      = params.get("bucketName", "")

    logger.info("CloudTrail event: %s on %s", event_name, bucket)

    if event_name == "PutBucketPolicy" and bucket:
        try:
            policy = json.loads(params.get("bucketPolicy", "{}"))
            if _policy_has_public_principal(policy):
                logger.warning("Public policy detected on %s – remediating", bucket)
                return _remediate_s3_public_access(
                    {}, {"s3BucketDetails": [{"name": bucket}]}
                )
        except (json.JSONDecodeError, TypeError):
            pass

    elif event_name == "PutPublicAccessBlock":
        config = params.get("PublicAccessBlockConfiguration", {})
        if not all([
            config.get("BlockPublicAcls", False),
            config.get("BlockPublicPolicy", False),
            config.get("RestrictPublicBuckets", False)
        ]):
            return _remediate_account_block_public_access({}, {})

    return {"action": "MONITORED", "event": event_name, "bucket": bucket}


# ─── HELPER FUNCTIONS ─────────────────────────────────────────────────────────
def _get_bucket_name(resource: dict) -> str:
    details = resource.get("s3BucketDetails", [])
    if details and isinstance(details, list):
        return details[0].get("name", "")
    return resource.get("resourceId", "")


def _remove_public_statements(policy: dict) -> dict:
    cleaned = []
    for stmt in policy.get("Statement", []):
        principal = stmt.get("Principal", {})
        is_public = (
            principal == "*"
            or principal == {"AWS": "*"}
            or (isinstance(principal, dict) and principal.get("AWS") == "*")
        )
        if is_public and stmt.get("Effect") == "Allow":
            logger.info("Removing public Allow statement: %s", stmt.get("Sid", "unnamed"))
        else:
            cleaned.append(stmt)
    policy["Statement"] = cleaned
    return policy


def _policy_has_public_principal(policy: dict) -> bool:
    for stmt in policy.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        p = stmt.get("Principal", {})
        if p == "*" or (isinstance(p, dict) and p.get("AWS") == "*"):
            return True
    return False


def _send_alert(title: str, message: str, severity: str = "MEDIUM") -> None:
    payload = {
        "title": title, "message": message, "severity": severity,
        "timestamp": _now(), "account": ACCOUNT_ID, "dry_run": DRY_RUN
    }
    if SNS_ALERT_TOPIC:
        try:
            get_client("sns").publish(
                TopicArn=SNS_ALERT_TOPIC,
                Subject=f"[{severity}] AWS Security Alert: {title[:50]}",
                Message=json.dumps(payload, indent=2),
                MessageAttributes={
                    "severity": {"DataType": "String", "StringValue": severity}
                }
            )
        except ClientError as e:
            logger.error("SNS publish failed: %s", e)

    if SLACK_WEBHOOK:
        _slack(title, message, severity)


def _slack(title: str, message: str, severity: str) -> None:
    import urllib.request
    colors = {"CRITICAL": "#FF0000", "HIGH": "#FF6600", "MEDIUM": "#FFCC00", "LOW": "#00AA00"}
    icons  = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
    body = json.dumps({
        "attachments": [{
            "color": colors.get(severity, "#808080"),
            "title": f"{icons.get(severity, '⚠️')} {title}",
            "text": message,
            "footer": f"AWS Security | {ACCOUNT_ID}",
            "ts": int(datetime.now(timezone.utc).timestamp())
        }]
    }).encode()
    try:
        req = urllib.request.Request(
            SLACK_WEBHOOK, data=body, headers={"Content-Type": "application/json"}
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        logger.warning("Slack notify failed (non-critical): %s", e)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
