# MedTech Security Compliance Checker

Automated AWS security compliance checking tool for MedTech's cloud infrastructure. This Lambda-based solution performs comprehensive security audits across S3, IAM, and EC2/Network services, with multi-region scanning and automated email notifications.

## Presentaion Recording
Link: https://cmu.zoom.us/rec/share/54nM74wvG-Gprh3mZ9jQql7EuGw2qAAJqi3FZO8Cx28VacJA-Fqvf3jGZ1Tm3zX1.vF9jntZ0Ups_bMdw
(Password: ^08dq@RQ)

## Features

- **Multi-Region Scanning**: Scans US AWS regions (us-east-1, us-east-2, us-west-1, us-west-2)
- **Severity Classification**: Categorizes findings as CRITICAL, HIGH, MEDIUM, or LOW
- **Automated Notifications**: Sends detailed compliance reports via SNS email
- **Scheduled Execution**: Runs daily via EventBridge trigger

## Security Checks

### S3 Buckets
| Check | Severity | Description |
|-------|----------|-------------|
| Public Buckets (ACL) | CRITICAL | Buckets with public access via ACL |
| Public Bucket Policies | CRITICAL | Buckets with public bucket policies |
| Unencrypted Buckets | HIGH | Buckets without default encryption |
| No Versioning | MEDIUM | Buckets without versioning enabled |
| No Logging | LOW | Buckets without access logging |

### IAM Security
| Check | Severity | Description |
|-------|----------|-------------|
| Users without MFA | HIGH | IAM users without MFA enabled |
| Old Access Keys | HIGH | Access keys older than 90 days |
| Unused Access Keys | MEDIUM | Access keys never used or unused for 90+ days |
| Admin Users | CRITICAL | Users with AdministratorAccess policy |
| Inactive Users | MEDIUM | Users who haven't logged in for 90+ days |
| Root Account Issues | CRITICAL | Root account without MFA or with access keys |

### Network Security
| Check | Severity | Description |
|-------|----------|-------------|
| Risky Security Groups | CRITICAL | Security groups allowing 0.0.0.0/0 on sensitive ports (22, 3389, 3306, etc.) |
| All Traffic Rules | CRITICAL | Security groups allowing all inbound traffic |
| Overly Permissive Outbound | MEDIUM | Security groups with unrestricted outbound access |

## Architecture
```
                    ┌─────────────────┐
                    │   EventBridge   │
                    │  (Daily Trigger)│
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │     Lambda      │
                    │   Function      │
                    └────────┬────────┘
                             │
           ┌─────────────────┼─────────────────┐
           │                 │                 │
           ▼                 ▼                 ▼
    ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
    │  S3 Checks  │   │ IAM Checks  │   │ EC2 Checks  │
    └─────────────┘   └─────────────┘   └─────────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │   SNS Topic     │
                    │  (Email Alert)  │
                    └─────────────────┘
```

## Project Structure
```
medtech-compliance-checker/
├── lambda_function.py      # Main Lambda handler
├── checks/
│   ├── __init__.py
│   ├── s3_checks.py        # S3 security checks
│   ├── iam_checks.py       # IAM security checks
│   └── ec2_checks.py       # EC2/Network security checks
├── requirements.txt        # Python dependencies
└── README.md
```

## Prerequisites

- AWS Account with appropriate permissions
- Python 3.9+
- AWS CLI configured with credentials

## Local Development

### Setup
```bash
# Clone repository
git clone https://github.com/e1inahuang/medtech-compliance-checker.git
cd medtech-compliance-checker

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure AWS CLI
aws configure
```

### Run Locally
```bash
# Run all checks
python lambda_function.py

# Run individual check modules
python -m checks.s3_checks
python -m checks.iam_checks
python -m checks.ec2_checks
```

## AWS Deployment

### 1. Create SNS Topic
```
AWS Console → SNS → Create topic
- Type: Standard
- Name: medtech-security-alerts
- Create email subscription and confirm
```

### 2. Create Lambda Function
```
AWS Console → Lambda → Create function
- Name: medtech-compliance-checker
- Runtime: Python 3.9
- Timeout: 10 minutes
- Memory: 512 MB
```

### 3. Deploy Code
```bash
# Package code
mkdir deployment
cp lambda_function.py deployment/
cp -r checks deployment/
cd deployment
zip -r ../lambda_deployment.zip .

# Upload via AWS Console
Lambda → Upload from → .zip file
```

### 4. Configure Permissions

Attach these policies to Lambda execution role:
- `AmazonS3ReadOnlyAccess`
- `IAMReadOnlyAccess`
- `AmazonEC2ReadOnlyAccess`
- `AmazonSNSFullAccess`

### 5. Set Up Scheduled Trigger
```
Lambda → Configuration → Triggers → Add trigger
- Source: EventBridge
- Rule: Create new rule
- Schedule: rate(1 day)
```

## Sample Output
```
======================================================================
COMPLIANCE CHECK SUMMARY
======================================================================
Timestamp: 2025-11-30T21:01:20.663828
Total Issues Found: 23

By Severity:
  CRITICAL: 19
  HIGH:     3
  MEDIUM:   1
  LOW:      0

----------------------------------------------------------------------
S3 BUCKETS
----------------------------------------------------------------------
  Public Buckets (ACL):     0 [CRITICAL]
  Public Bucket Policies:   0 [CRITICAL]
  Unencrypted Buckets:      0 [HIGH]
  No Versioning:            0 [MEDIUM]
  No Logging:               0 [LOW]

----------------------------------------------------------------------
IAM SECURITY
----------------------------------------------------------------------
  Users without MFA:        3 [HIGH]
  Old Access Keys (>90d):   0 [HIGH]
  Unused Access Keys:       0 [MEDIUM]
  Admin Users:              1 [CRITICAL]
  Inactive Users:           1 [MEDIUM]
  Root Account Issues:      0 [CRITICAL]

----------------------------------------------------------------------
NETWORK SECURITY
----------------------------------------------------------------------
  Risky Security Groups:    18 [CRITICAL]
======================================================================
```

## AWS Services Used

| Service | Purpose |
|---------|---------|
| Lambda | Runs compliance checks |
| EventBridge | Schedules daily execution |
| SNS | Sends email notifications |
| IAM | Access management and audit target |
| S3 | Audit target |
| EC2 | Security group audit target |

## Cost Estimate

- Lambda: ~$0.50/month (daily execution, ~2 min runtime)
- SNS: ~$0.10/month (daily email notifications)
- **Total: < $1/month**

## Future Enhancements

- [ ] Add CloudTrail log analysis
- [ ] Add RDS security checks
- [ ] Add compliance framework mapping (CIS, HIPAA)
- [ ] Add Slack/Teams notification integration
- [ ] Add remediation automation
- [ ] Add dashboard visualization (CloudWatch)

## License

MIT License

## Contributors

- Elina Huang
- Jasmine Cai
- Yulin Xue
