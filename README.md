# MedTech Security Compliance Checker

Automated security compliance checking for MedTech's AWS infrastructure.

## Team Members
- [Your Name] - Lead, Lambda main function, SNS notifications
- [Teammate 1] - S3 and IAM checks
- [Teammate 2] - EC2/Security group checks, Architecture diagram

## Project Structure
medtech-compliance-checker/ ├── lambda_function.py # Main Lambda function ├── checks/ │ ├── s3_checks.py # S3 security checks │ ├── iam_checks.py # IAM security checks │ └── ec2_checks.py # EC2/Network checks ├── template.yaml # CloudFormation template └── requirements.txt # Python dependencies

## Security Checks
1. **S3 Buckets**: Public access, encryption status
2. **IAM Users**: MFA compliance
3. **Security Groups**: Overly permissive rules (0.0.0.0/0)

## Setup
```bash
# Clone repo
git clone [repo-url]
cd medtech-compliance-checker

# Install dependencies
pip install -r requirements.txt

# Configure AWS CLI
aws configure
Local Testing
python lambda_function.py