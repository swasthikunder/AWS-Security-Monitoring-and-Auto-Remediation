# AWS S3 & IAM Security Monitoring Architecture

## Overview

This project implements a security-focused AWS environment using Infrastructure as Code (Terraform). The architecture is designed to detect, monitor, and respond to security events affecting Amazon S3 and AWS IAM resources.

## Architecture Components

### Secure S3 Storage

* S3 Bucket with Block Public Access enabled
* Versioning enabled
* Server-side encryption enabled
* HTTPS-only access enforcement

### IAM Hardening

* Least-privilege IAM policies
* Dedicated application roles
* Security monitoring permissions
* Automated remediation permissions

### Monitoring Layer

* AWS CloudTrail for API activity logging
* Amazon CloudWatch Logs for centralized log collection
* CloudWatch Metric Filters for security event detection
* CloudWatch Alarms for alert generation

### Automated Response

* Amazon EventBridge event routing
* AWS Lambda remediation functions
* Amazon SNS security notifications

## Security Event Flow

1. User performs an AWS action.
2. CloudTrail records the API event.
3. CloudWatch evaluates security filters.
4. Security alarms trigger when suspicious activity is detected.
5. EventBridge routes the event.
6. Lambda executes remediation actions.
7. SNS sends security alerts.

## Key Security Controls

* Public S3 bucket detection
* Unauthorized API call detection
* Root account usage monitoring
* IAM policy change monitoring
* CloudTrail modification monitoring
* Bucket deletion monitoring

## Deployment Model

Environment:

* Development (dev)

Infrastructure Management:

* Terraform

Cloud Provider:

* Amazon Web Services (AWS)

Monitoring:

* CloudWatch
* CloudTrail
* SNS
* EventBridge

Automation:

* AWS Lambda

## Enterprise Features

The following enterprise-grade controls are included in the Terraform codebase but are disabled by default for free-tier deployments:

- AWS GuardDuty
- AWS Config
- AWS Security Hub
- AWS KMS Customer Managed Keys

These services can be enabled for production deployments by uncommenting the relevant Terraform resources.