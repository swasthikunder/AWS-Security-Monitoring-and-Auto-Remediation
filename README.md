# 🔐 AWS Cloud Security Monitoring & Automated Remediation Platform

> Enterprise-style AWS cloud security monitoring, threat detection, alerting, and automated remediation solution built using Terraform and AWS-native security services.

![Terraform](https://img.shields.io/badge/Terraform-v1.0+-623CE4?style=for-the-badge\&logo=terraform)
![AWS](https://img.shields.io/badge/AWS-Cloud_Security-FF9900?style=for-the-badge\&logo=amazonaws)
![Security](https://img.shields.io/badge/Security-Detection_Engineering-red?style=for-the-badge)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Automation-blue?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

---

# 📌 Overview

Modern cloud environments generate thousands of API calls and configuration changes every day. Without continuous monitoring, security misconfigurations and unauthorized actions can remain undetected, increasing the risk of data exposure and privilege escalation.

This project implements a real-time AWS security monitoring and automated remediation platform focused on securing Amazon S3 environments.

The solution combines Infrastructure as Code (Terraform), centralized logging, security alerting, event-driven automation, and automated remediation to improve cloud visibility and security posture.

The architecture follows:

* AWS Well-Architected Security Pillar
* CIS AWS Foundations Benchmark
* AWS Security Best Practices
* Least Privilege Access Control
* Defense-in-Depth Principles
* Security Monitoring & Detection Engineering Practices

---

# 🚀 Core Features

## 🔐 S3 Security Hardening

* S3 Versioning Enabled
* Server-Side Encryption (SSE-S3)
* Public Access Block Enabled
* Server Access Logging
* Compliance-Oriented Resource Tagging
* Secure Bucket Configuration

---

## 👤 IAM Security

* Custom Application IAM Role
* Least Privilege Access Model
* Scoped S3 Permissions
* Service Trust Relationships
* IAM Access Analyzer Integration

---

## 📜 Logging & Auditability

* Multi-Region CloudTrail
* CloudTrail Log Validation
* CloudWatch Log Integration
* Centralized Security Logging
* API Activity Monitoring
* Security Event Tracking

---

## 🚨 Security Monitoring

Real-time detection for:

* Unauthorized API Calls
* IAM Policy Changes
* CloudTrail Configuration Changes
* S3 Public Access Changes
* Root Account Usage
* Console Login Without MFA
* GuardDuty Disable Attempts
* S3 Bucket Deletion Events
* KMS Key Deletion Events

---

## 🔔 Security Alerting

* CloudWatch Alarms
* SNS Notifications
* Email-Based Incident Alerts
* Security Event Notifications
* Automated Incident Visibility

---

## 🤖 Automated Remediation

* EventBridge Security Automation
* Lambda-Based Response Workflow
* Real-Time Event Processing
* Security Validation Logic
* Automated Response Actions

---

# 🏗️ Security Architecture

```text
                    ┌─────────────────────┐
                    │     CloudTrail      │
                    │   Security Events   │
                    └──────────┬──────────┘
                               │
                               ▼

                    ┌─────────────────────┐
                    │  CloudWatch Logs    │
                    │ Centralized Logging │
                    └──────────┬──────────┘
                               │
              ┌────────────────┴────────────────┐
              ▼                                 ▼

     ┌──────────────────┐             ┌──────────────────┐
     │ CloudWatch Alarm │             │   EventBridge    │
     │ Security Metrics │             │ Security Routing │
     └────────┬─────────┘             └────────┬─────────┘
              │                                │
              ▼                                ▼

     ┌──────────────────┐             ┌──────────────────┐
     │   SNS Alerts     │             │ Lambda Function  │
     │ Email Notification│            │ Auto Remediation │
     └──────────────────┘             └────────┬─────────┘
                                                │
                                                ▼

                                      ┌──────────────────┐
                                      │ Secure S3 State  │
                                      └──────────────────┘
```

---

# 🧠 Real-World Use Case

This project simulates how cloud security teams monitor AWS environments for suspicious activity and automatically respond to security-sensitive events.

The architecture focuses on:

* Improving cloud visibility
* Detecting risky configuration changes
* Monitoring critical AWS API activity
* Generating actionable alerts
* Automating incident response
* Maintaining audit trails
* Reducing operational response time

This project can serve as:

* Cloud Security Portfolio Project
* Detection Engineering Project
* DevSecOps Learning Environment
* AWS Security Monitoring Reference Architecture
* Security Automation Demonstration

---

# 🛠️ Technologies Used

| Technology          | Purpose                      |
| ------------------- | ---------------------------- |
| Terraform           | Infrastructure as Code       |
| Amazon S3           | Secure Storage               |
| IAM                 | Identity & Access Management |
| IAM Access Analyzer | Permission Visibility        |
| CloudTrail          | Audit Logging                |
| CloudWatch          | Monitoring & Alerting        |
| SNS                 | Alert Notifications          |
| EventBridge         | Event Routing                |
| Lambda              | Automated Remediation        |
| AWS CLI             | Security Testing             |

---

# 📂 Project Structure

```text
aws-s3-iam-security/
│
├── environments/
│   └── dev/
│
├── modules/
│   ├── s3/
│   ├── iam/
│   ├── cloudtrail/
│   ├── cloudwatch/
│   ├── sns/
│   ├── lambda/
│   └── eventbridge/
│
├── lambda/
│   └── auto_remediation.py
│
├── screenshots/
│
├── README.md
│
└── architecture/

```

---

# ⚙️ Deployment Workflow

## Initialize Terraform

```bash
terraform init
```

## Validate Configuration

```bash
terraform validate
```

## Preview Infrastructure Changes

```bash
terraform plan
```

## Deploy Infrastructure

```bash
terraform apply
```

---

# 📋 Prerequisites

Before deployment ensure:

* Terraform >= 1.5
* AWS CLI Installed
* AWS Credentials Configured
* Appropriate IAM Permissions
* MFA Enabled on Root Account

Verify credentials:

```bash
aws sts get-caller-identity
```

---

# 🔒 Security Controls Implemented

| Category              | Controls                        |
| --------------------- | ------------------------------- |
| S3 Security           | Encryption, Versioning, Logging |
| IAM                   | Least Privilege Roles           |
| Monitoring            | CloudWatch Alarms               |
| Logging               | CloudTrail + CloudWatch         |
| Alerting              | SNS Notifications               |
| Automation            | EventBridge + Lambda            |
| Detection Engineering | Security Metric Filters         |
| Governance            | Access Analyzer                 |

---

# 🧪 Security Validation Performed

The environment was validated using controlled security testing.

## Tested Scenarios

### Unauthorized API Detection

```bash
aws iam delete-user --user-name fake-user
```

### S3 Public Access Modification

```bash
aws s3api delete-public-access-block \
  --bucket <bucket-name>
```

### IAM Policy Change Monitoring

```bash
aws iam attach-role-policy ...
```

### CloudTrail Monitoring Validation

```bash
aws cloudtrail lookup-events
```

---

# 🔥 Security Incident Simulation

The monitoring platform was validated by simulating a security-sensitive
change to an S3 bucket.

## Attack Simulation

Command executed:

aws s3api delete-public-access-block \
  --bucket s3iam-sec-dev-77fb3d48

## Detection Flow

1. CloudTrail captured DeletePublicAccessBlock API call
2. EventBridge matched the event pattern
3. Lambda remediation function executed
4. CloudWatch alarm entered ALARM state
5. SNS email alert was delivered
6. Security logs were recorded for investigation

## Outcome

The platform successfully detected the security event and generated
real-time alerts for incident response.

---

# 📸 Development & Validation Evidence

## Infrastructure as Code (Terraform)

### Terraform Initialization & Validation

<p align="center">
  <img src="screenshots/terraform-init-validate.png" width="75%">
</p>

Terraform successfully initialized providers and validated all infrastructure configurations before deployment.

---

### Terraform Execution Plan

<p align="center">
  <img src="screenshots/terraform-plan.png" width="75%">
</p>

Terraform execution plan showing proposed infrastructure changes before deployment.

---

### Terraform Deployment

<p align="center">
  <img src="screenshots/terraform-apply.png" width="75%">
</p>

Successful deployment of the AWS security monitoring environment using Infrastructure as Code.

---

## Amazon S3 Security Hardening

### Secure S3 Bucket Configuration

<p align="center">
  <img src="screenshots/s3-buckets.png" width="48%">
</p>

<p align="center">
  <img src="screenshots/s3-security-controls.png" width="48%">
</p>

Configured secure S3 storage with public access restrictions and hardened bucket controls.

---

### Bucket Versioning & Encryption

<p align="center">
  <img src="screenshots/s3-versioning-enabled.png" width="48%">
</p>


<p align="center">
  <img src="screenshots/s3-default-encryption.png" width="48%">
</p>


Enabled object versioning and server-side encryption for data protection and recovery.

---

## IAM Security Controls

### Least Privilege Application Role

<p align="center">
  <img src="screenshots/iam-least-privilege-role.png" width="48%">
</p>


<p align="center">
  <img src="screenshots/iam-trust-relationships.png" width="48%">
</p>


Implemented IAM least-privilege access controls and trust policies for secure service interactions.

---

### IAM Role Management

<p align="center">
  <img src="screenshots/iam-roles-overview.png" width="48%">
</p>


<p align="center">
  <img src="screenshots/iam-access-analyzer.png" width="48%">
</p>

IAM Access Analyzer continuously evaluates resource exposure and validates access boundaries.

---

## CloudTrail Auditing

### CloudTrail Configuration

<p align="center">
  <img src="screenshots/cloudtrail-dashboard.png" width="48%">
</p>


<p align="center">
  <img src="screenshots/cloudtrail-security-trail.png" width="48%">
</p>

CloudTrail configured to capture and retain AWS management events for auditing and investigation.

---

### Security Event Capture

<p align="center">
  <img src="screenshots/cloudtrail-delete-public-access-block.png" width="75%">
</p>

CloudTrail recorded a security-sensitive S3 configuration change event used for detection and response validation.

---

## CloudWatch Monitoring & Detection

### Security Alarm Configuration

<p align="center">
  <img src="screenshots/cloudwatch-security-alarms.png" width="75%">
</p>

CloudWatch alarms configured to detect:

- Unauthorized API calls
- Root account activity
- IAM policy changes
- CloudTrail modifications
- S3 public access changes
- S3 bucket deletion
- KMS key deletion
- GuardDuty disablement

---

### Alarm Dashboard

<p align="center">
  <img src="screenshots/cloudwatch-security-alarms-dashboard.png" width="75%">
</p>

Centralized monitoring dashboard displaying active security detections and alarm states.

---

### Log Collection

<p align="center">
  <img src="screenshots/cloudwatch-log-groups.png" width="48%">
</p>

<p align="center">
  <img src="screenshots/cloudwatch-lambda-log-group.png" width="48%">
</p>

CloudWatch Log Groups collect operational, audit, and remediation logs for investigation and troubleshooting.

---

## Event-Driven Security Automation

### EventBridge Detection Rules

<p align="center">
  <img src="screenshots/eventbridge-security-rules.png" width="48%">
</p>

<p align="center">
  <img src="screenshots/eventbridge-rule-lambda-target.png" width="48%">
</p>

EventBridge rules detect security events and route them to automated remediation workflows.

---

### Remediation Trigger

<p align="center">
  <img src="screenshots/eventbridge-remediation-trigger.png" width="75%">
</p>

Security events automatically invoke remediation logic through EventBridge-to-Lambda integration.

---

## Automated Remediation

### Lambda Security Automation

<p align="center">
  <img src="screenshots/lambda-auto-remediation-function.png" width="48%">
</p>

<p align="center">
  <img src="screenshots/lambda-auto-remediation-architecture.png" width="48%">
</p>

AWS Lambda performs automated security response actions based on detected events.

---

### Lambda Configuration

<p align="center">
  <img src="screenshots/lambda-remediation-environment-variables.png" width="75%">
</p>

Environment-driven configuration supports alert routing, dry-run testing, and controlled remediation behavior.

---

## Security Alerting

### SNS Alert Topics

<p align="center">
  <img src="screenshots/sns-email-subscriptions.png" width="48%">
</p>

SNS topics distribute security notifications to subscribed recipients.

---

## CloudTrail Logging

<p align="center">
  <img src="screenshots/cloudtrail-dashboard.png" width="48%">
</p>


## Security Alerting

<p align="center">
  <img src="screenshots/sns-topics.png" width="48%">
</p>

<p align="center">
  <img src="screenshots/email-alerts.png" width="48%">
</p>

---

# 🧠 Skills Demonstrated

* AWS Cloud Security
* Detection Engineering
* Security Monitoring
* Security Automation
* Infrastructure as Code
* IAM Governance
* Cloud Logging & Alerting
* Incident Response
* DevSecOps Practices
* Event-Driven Security Architecture

---

# 🏆 Resume Highlights

* Designed and implemented an AWS security monitoring and automated remediation platform using Terraform and AWS-native security services.
* Built real-time detection pipelines using CloudTrail, CloudWatch, SNS, EventBridge, and Lambda.
* Implemented automated alerting and response workflows for S3 security-related events.
* Applied IAM least-privilege principles and security governance controls.
* Developed modular Infrastructure-as-Code architecture using reusable Terraform modules.
* Simulated cloud security operations workflows including detection, alerting, and remediation.

---

# Lessons Learned

During development several issues were encountered:

- EventBridge rules initially failed to invoke Lambda
- CloudTrail event propagation introduced delays
- Lambda permissions required troubleshooting
- CloudWatch metric filters required fine tuning

These challenges improved understanding of
AWS event-driven security architectures.

---

# 🚧 Future Enhancements

- [ ] AWS Security Hub Integration
- [ ] Slack Incident Notifications
- [ ] Automated IAM Key Rotation
- [ ] AWS Config Compliance Monitoring
- [ ] Multi-Account Security Monitoring
- [ ] SIEM Integration (Splunk / ELK)
- [ ] Automated SOAR Workflows

---
# 👥 Contributors

Swasthi Kunder — Project Lead, Development & Security Engineering

Sakshat S — Contributor (Testing & Documentation)
---

# 💰 Cost Considerations

This project was designed to remain within AWS Free Tier
where possible.

Primary billable services:

- CloudTrail
- CloudWatch Logs
- SNS
- Lambda

Estimated testing cost:
< $2 USD

---
# ⭐ Final Notes

This project demonstrates how Infrastructure as Code, AWS-native security services, and event-driven automation can be combined to build a practical cloud security monitoring and response platform.

The focus extends beyond deployment automation to include:

* Security Visibility
* Threat Detection
* Monitoring & Alerting
* Governance Controls
* Incident Response
* Security Automation
* Cloud Security Engineering

If you found this project useful, consider giving it a ⭐ on GitHub.
