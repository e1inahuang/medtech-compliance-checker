"""
MedTech Security Compliance Checker
Main Lambda function that orchestrates all security checks
"""
import json
import boto3
from datetime import datetime
from botocore.exceptions import ClientError

from checks.s3_checks import (
    check_public_buckets,
    check_public_bucket_policy,
    check_unencrypted_buckets,
    check_bucket_versioning,
    check_bucket_logging
)
from checks.iam_checks import (
    check_mfa_compliance,
    check_access_key_age,
    check_unused_access_keys,
    check_admin_users,
    check_inactive_users,
    check_root_account
)
from checks.ec2_checks import check_security_groups


SNS_TOPIC_ARN = 'arn:aws:sns:us-east-1:218550332126:medtech-security-alerts'


def lambda_handler(event, context):
    """
    Main Lambda handler - orchestrates all security checks
    """
    print("=" * 70)
    print("MedTech Security Compliance Check Started")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print("=" * 70)

    findings = run_all_checks()

    if findings is None:
        return {
            'statusCode': 500,
            'body': json.dumps('Error during compliance check')
        }

    total_issues = calculate_total_issues(findings)
    findings['total_issues'] = total_issues
    findings['severity_summary'] = calculate_severity_summary(findings)

    print_summary(findings)

    if total_issues > 0:
        print("\nSending notification...")
        notification_sent = send_notification(findings)
        if notification_sent:
            print("[OK] Notification sent successfully")
        else:
            print("[WARNING] Failed to send notification")
    else:
        print("\n[OK] No issues found - no notification needed")

    return {
        'statusCode': 200,
        'body': json.dumps({
            'message': 'Compliance check completed',
            'total_issues': total_issues,
            'severity_summary': findings['severity_summary'],
            'findings': findings
        }, default=str)
    }


def run_all_checks():
    """
    Run all security checks and collect findings
    """
    try:
        # S3 Checks
        print("\n[STEP 1/3] S3 Security Checks")
        print("-" * 50)
        public_buckets = check_public_buckets()
        public_policies = check_public_bucket_policy()
        unencrypted_buckets = check_unencrypted_buckets()
        no_versioning = check_bucket_versioning()
        no_logging = check_bucket_logging()

        # IAM Checks
        print("\n[STEP 2/3] IAM Security Checks")
        print("-" * 50)
        users_without_mfa = check_mfa_compliance()
        old_access_keys = check_access_key_age()
        unused_access_keys = check_unused_access_keys()
        admin_users = check_admin_users()
        inactive_users = check_inactive_users()
        root_issues = check_root_account()

        # EC2/Network Checks
        print("\n[STEP 3/3] Network Security Checks")
        print("-" * 50)
        risky_security_groups = check_security_groups()

        findings = {
            'timestamp': datetime.now().isoformat(),
            'checks': {
                's3': {
                    'public_buckets': {
                        'count': len(public_buckets),
                        'items': public_buckets,
                        'severity': 'CRITICAL'
                    },
                    'public_policies': {
                        'count': len(public_policies),
                        'items': public_policies,
                        'severity': 'CRITICAL'
                    },
                    'unencrypted_buckets': {
                        'count': len(unencrypted_buckets),
                        'items': unencrypted_buckets,
                        'severity': 'HIGH'
                    },
                    'no_versioning': {
                        'count': len(no_versioning),
                        'items': no_versioning,
                        'severity': 'MEDIUM'
                    },
                    'no_logging': {
                        'count': len(no_logging),
                        'items': no_logging,
                        'severity': 'LOW'
                    }
                },
                'iam': {
                    'users_without_mfa': {
                        'count': len(users_without_mfa),
                        'items': users_without_mfa,
                        'severity': 'HIGH'
                    },
                    'old_access_keys': {
                        'count': len(old_access_keys),
                        'items': old_access_keys,
                        'severity': 'HIGH'
                    },
                    'unused_access_keys': {
                        'count': len(unused_access_keys),
                        'items': unused_access_keys,
                        'severity': 'MEDIUM'
                    },
                    'admin_users': {
                        'count': len(admin_users),
                        'items': admin_users,
                        'severity': 'CRITICAL'
                    },
                    'inactive_users': {
                        'count': len(inactive_users),
                        'items': inactive_users,
                        'severity': 'MEDIUM'
                    },
                    'root_issues': {
                        'count': len(root_issues),
                        'items': root_issues,
                        'severity': 'CRITICAL'
                    }
                },
                'network': {
                    'risky_security_groups': {
                        'count': len(risky_security_groups),
                        'items': risky_security_groups,
                        'severity': 'CRITICAL'
                    }
                }
            }
        }

        return findings

    except Exception as e:
        print(f"[ERROR] Error during checks: {e}")
        return None


def calculate_total_issues(findings):
    """Calculate total number of issues found"""
    total = 0
    for category in findings['checks'].values():
        for check_data in category.values():
            total += check_data['count']
    return total


def calculate_severity_summary(findings):
    """Calculate issues by severity level"""
    summary = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}

    for category in findings['checks'].values():
        for check_data in category.values():
            severity = check_data['severity']
            count = check_data['count']
            if severity in summary:
                summary[severity] += count

    return summary


def print_summary(findings):
    """Print a summary of all findings"""
    print("\n" + "=" * 70)
    print("COMPLIANCE CHECK SUMMARY")
    print("=" * 70)
    print(f"Timestamp: {findings['timestamp']}")
    print(f"Total Issues Found: {findings['total_issues']}")

    severity = findings['severity_summary']
    print(f"\nBy Severity:")
    print(f"  CRITICAL: {severity['CRITICAL']}")
    print(f"  HIGH:     {severity['HIGH']}")
    print(f"  MEDIUM:   {severity['MEDIUM']}")
    print(f"  LOW:      {severity['LOW']}")

    print("\n" + "-" * 70)
    print("S3 BUCKETS")
    print("-" * 70)
    s3 = findings['checks']['s3']
    print(f"  Public Buckets (ACL):     {s3['public_buckets']['count']} [{s3['public_buckets']['severity']}]")
    print(f"  Public Bucket Policies:   {s3['public_policies']['count']} [{s3['public_policies']['severity']}]")
    print(f"  Unencrypted Buckets:      {s3['unencrypted_buckets']['count']} [{s3['unencrypted_buckets']['severity']}]")
    print(f"  No Versioning:            {s3['no_versioning']['count']} [{s3['no_versioning']['severity']}]")
    print(f"  No Logging:               {s3['no_logging']['count']} [{s3['no_logging']['severity']}]")

    print("\n" + "-" * 70)
    print("IAM SECURITY")
    print("-" * 70)
    iam = findings['checks']['iam']
    print(f"  Users without MFA:        {iam['users_without_mfa']['count']} [{iam['users_without_mfa']['severity']}]")
    print(f"  Old Access Keys (>90d):   {iam['old_access_keys']['count']} [{iam['old_access_keys']['severity']}]")
    print(f"  Unused Access Keys:       {iam['unused_access_keys']['count']} [{iam['unused_access_keys']['severity']}]")
    print(f"  Admin Users:              {iam['admin_users']['count']} [{iam['admin_users']['severity']}]")
    print(f"  Inactive Users:           {iam['inactive_users']['count']} [{iam['inactive_users']['severity']}]")
    print(f"  Root Account Issues:      {iam['root_issues']['count']} [{iam['root_issues']['severity']}]")

    print("\n" + "-" * 70)
    print("NETWORK SECURITY")
    print("-" * 70)
    network = findings['checks']['network']
    print(f"  Risky Security Groups:    {network['risky_security_groups']['count']} [{network['risky_security_groups']['severity']}]")

    print("=" * 70)


def send_notification(findings):
    """Send SNS notification with findings"""
    sns = boto3.client('sns')
    message = format_notification_message(findings)

    try:
        response = sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject='[ALERT] MedTech Security Compliance Report',
            Message=message
        )
        print(f"Notification MessageId: {response['MessageId']}")
        return True

    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'InvalidParameter':
            print("[ERROR] Invalid SNS Topic ARN. Please update SNS_TOPIC_ARN in the code.")
        else:
            print(f"[ERROR] Error sending notification: {e}")
        return False


def format_notification_message(findings):
    """Format findings into readable email message"""
    total = findings['total_issues']
    severity = findings['severity_summary']
    timestamp = findings['timestamp']

    # Determine overall severity
    if severity['CRITICAL'] > 0:
        overall = "CRITICAL"
    elif severity['HIGH'] > 0:
        overall = "HIGH"
    elif severity['MEDIUM'] > 0:
        overall = "MEDIUM"
    else:
        overall = "LOW"

    message = f"""
MedTech Security Compliance Report
=====================================
Generated: {timestamp}
Overall Severity: {overall}

TOTAL ISSUES FOUND: {total}

By Severity:
  CRITICAL: {severity['CRITICAL']}
  HIGH:     {severity['HIGH']}
  MEDIUM:   {severity['MEDIUM']}
  LOW:      {severity['LOW']}

=====================================
S3 BUCKETS
=====================================
Public Buckets (ACL): {findings['checks']['s3']['public_buckets']['count']}
{format_item_list(findings['checks']['s3']['public_buckets']['items'])}

Public Bucket Policies: {findings['checks']['s3']['public_policies']['count']}
{format_item_list(findings['checks']['s3']['public_policies']['items'])}

Unencrypted Buckets: {findings['checks']['s3']['unencrypted_buckets']['count']}
{format_item_list(findings['checks']['s3']['unencrypted_buckets']['items'])}

No Versioning: {findings['checks']['s3']['no_versioning']['count']}
{format_item_list(findings['checks']['s3']['no_versioning']['items'])}

=====================================
IAM SECURITY
=====================================
Users without MFA: {findings['checks']['iam']['users_without_mfa']['count']}
{format_item_list(findings['checks']['iam']['users_without_mfa']['items'])}

Old Access Keys (>90 days): {findings['checks']['iam']['old_access_keys']['count']}
{format_item_list(findings['checks']['iam']['old_access_keys']['items'])}

Unused Access Keys: {findings['checks']['iam']['unused_access_keys']['count']}
{format_item_list(findings['checks']['iam']['unused_access_keys']['items'])}

Admin Users: {findings['checks']['iam']['admin_users']['count']}
{format_item_list(findings['checks']['iam']['admin_users']['items'])}

Inactive Users: {findings['checks']['iam']['inactive_users']['count']}
{format_item_list(findings['checks']['iam']['inactive_users']['items'])}

Root Account Issues: {findings['checks']['iam']['root_issues']['count']}
{format_item_list(findings['checks']['iam']['root_issues']['items'])}

=====================================
NETWORK SECURITY
=====================================
Risky Security Groups: {findings['checks']['network']['risky_security_groups']['count']}
{format_item_list(findings['checks']['network']['risky_security_groups']['items'])}

=====================================
ACTION REQUIRED
=====================================
Please review these findings in the AWS Console.

Priority Guidelines:
- CRITICAL: Address within 24 hours
- HIGH: Address within 1 week
- MEDIUM: Address within 1 month
- LOW: Address as resources allow

For assistance, contact: security@medtech.com
    """

    return message.strip()


def format_item_list(items):
    """Helper function to format list items for notification"""
    if not items:
        return "  (none)"

    formatted = []
    for item in items:
        formatted.append(f"  - {item}")
    return "\n".join(formatted)


if __name__ == "__main__":
    print("Running local test...\n")
    result = lambda_handler({}, {})
    print("\n" + "=" * 70)
    print("LAMBDA RETURN VALUE:")
    print("=" * 70)
    print(json.dumps(json.loads(result['body']), indent=2, default=str))