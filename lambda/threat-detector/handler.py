import json
import boto3
from datetime import datetime, timezone

cloudtrail = boto3.client("cloudtrail")

SUSPICIOUS_EVENTS = [
    "DeleteTrail",
    "StopLogging",
    "DeleteBucket",
    "DeleteBucketPolicy",
    "PutBucketAcl",
    "PutBucketPolicy",
    "CreateAccessKey",
    "DeleteAccessKey",
    "AttachUserPolicy",
    "PutUserPolicy",
    "CreateLoginProfile"
]


def lambda_handler(event, context):

    findings = []

    try:
        response = cloudtrail.lookup_events(
            MaxResults=50
        )

        for record in response.get("Events", []):

            event_name = record.get("EventName", "")
            username = record.get("Username", "Unknown")

            if event_name in SUSPICIOUS_EVENTS:

                findings.append({
                    "event_name": event_name,
                    "user": username,
                    "event_time": str(record.get("EventTime"))
                })

        return {
            "statusCode": 200,
            "body": json.dumps({
                "scan_time": datetime.now(timezone.utc).isoformat(),
                "suspicious_events_found": len(findings),
                "findings": findings
            }, indent=2)
        }

    except Exception as e:

        return {
            "statusCode": 500,
            "body": json.dumps({
                "error": str(e)
            })
        }