# Compliance Mapping

## CIS AWS Foundations Benchmark

| Control           | Implementation      |
| ----------------- | ------------------- |
| Secure S3 Storage | Block Public Access |
| Logging Enabled   | CloudTrail          |
| Monitoring        | CloudWatch          |
| Least Privilege   | IAM Policies        |
| Root Monitoring   | CloudWatch Alerts   |
| Change Detection  | EventBridge         |

---

## SOC 2

### Security

Implemented Controls:

* Access management
* Monitoring
* Alerting
* Logging

Evidence:

* IAM policies
* CloudTrail logs
* CloudWatch alarms

---

### Availability

Implemented Controls:

* Centralized monitoring
* Automated alerting

Evidence:

* SNS notifications
* EventBridge rules

---

### Confidentiality

Implemented Controls:

* Encryption
* Secure transport
* Access restrictions

Evidence:

* S3 encryption
* HTTPS-only access

---

## AWS Security Best Practices

### Identity and Access Management

Implemented:

* Least privilege
* Role-based access

### Logging and Monitoring

Implemented:

* CloudTrail
* CloudWatch

### Incident Response

Implemented:

* Lambda remediation
* SNS alerts

### Data Protection

Implemented:

* S3 encryption
* Public access restrictions

## Cost Optimization Note

This project is intentionally designed for AWS Free Tier and educational use.

Enterprise monitoring services such as AWS Config, GuardDuty, Security Hub, and KMS Customer Managed Keys are included in the Terraform codebase as commented examples but are disabled by default to avoid unnecessary costs.