"""
MedTech Security Compliance Checker
Main Lambda function that orchestrates all security checks
"""
import json
import boto3
from datetime import datetime
from botocore.exceptions import ClientError

from checks.s3_checks import check_public_buckets, check_unencrypted_buckets
from checks.iam_checks import check_mfa_compliance
from checks.ec2_checks import check_security_groups


# Configuration - UPDATE THIS AFTER CREATING SNS TOPIC
SNS_TOPIC_ARN = 'arn:aws:sns:us-east-1:YOUR-ACCOUNT-ID:medtech-security-alerts'


def lambda_handler(event, context):
    """
    Main Lambda handler - orchestrates all security checks
    
    Args:
        event: Lambda event (not used for scheduled runs)
        context: Lambda context
        
    Returns:
        dict: Status code and findings summary
    """
    print("=" * 60)
    print("MedTech Security Compliance Check Started")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print("=" * 60)
    
    # Step 1: Run all security checks
    findings = run_all_checks()
    
    if findings is None:
        return {
            'statusCode': 500,
            'body': json.dumps('Error during compliance check')
        }
    
    # Step 2: Calculate total issues
    total_issues = calculate_total_issues(findings)
    findings['total_issues'] = total_issues
    
    # Step 3: Print summary
    print_summary(findings)
    
    # Step 4: Send notification if issues found
    if total_issues > 0:
        print("\nSending notification...")
        notification_sent = send_notification(findings)
        if notification_sent:
            print("[OK] Notification sent successfully")
        else:
            print("[WARNING] Failed to send notification")
    else:
        print("\n[OK] No issues found - no notification needed")
    
    # Step 5: Return results
    return {
        'statusCode': 200,
        'body': json.dumps({
            'message': 'Compliance check completed',
            'total_issues': total_issues,
            'findings': findings
        }, default=str)
    }


def run_all_checks():
    """
    Run all security checks and collect findings
    
    Returns:
        dict: All findings organized by check type
    """
    try:
        print("\n[STEP 1/3] Checking S3 buckets...")
        public_buckets = check_public_buckets()
        unencrypted_buckets = check_unencrypted_buckets()
        
        print("\n[STEP 2/3] Checking IAM users...")
        users_without_mfa = check_mfa_compliance()
        
        print("\n[STEP 3/3] Checking security groups...")
        risky_security_groups = check_security_groups()
        
        findings = {
            'timestamp': datetime.now().isoformat(),
            'checks': {
                'public_s3_buckets': {
                    'count': len(public_buckets),
                    'items': public_buckets,
                    'severity': 'CRITICAL'
                },
                'unencrypted_s3_buckets': {
                    'count': len(unencrypted_buckets),
                    'items': unencrypted_buckets,
                    'severity': 'HIGH'
                },
                'users_without_mfa': {
                    'count': len(users_without_mfa),
                    'items': users_without_mfa,
                    'severity': 'HIGH'
                },
                'risky_security_groups': {
                    'count': len(risky_security_groups),
                    'items': risky_security_groups,
                    'severity': 'CRITICAL'
                }
            }
        }
        
        return findings
        
    except Exception as e:
        print(f"[ERROR] Error during checks: {e}")
        return None


def calculate_total_issues(findings):
    """
    Calculate total number of issues found
    
    Args:
        findings: dict containing all check results
        
    Returns:
        int: Total number of issues
    """
    total = 0
    for check_name, check_data in findings['checks'].items():
        total += check_data['count']
    return total


def print_summary(findings):
    """
    Print a summary of all findings
    
    Args:
        findings: dict containing all check results
    """
    print("\n" + "=" * 60)
    print("COMPLIANCE CHECK SUMMARY")
    print("=" * 60)
    print(f"Timestamp: {findings['timestamp']}")
    print(f"Total Issues Found: {findings['total_issues']}")
    print("-" * 60)
    
    checks = findings['checks']
    print(f"  Public S3 Buckets:      {checks['public_s3_buckets']['count']} ({checks['public_s3_buckets']['severity']})")
    print(f"  Unencrypted S3 Buckets: {checks['unencrypted_s3_buckets']['count']} ({checks['unencrypted_s3_buckets']['severity']})")
    print(f"  Users without MFA:      {checks['users_without_mfa']['count']} ({checks['users_without_mfa']['severity']})")
    print(f"  Risky Security Groups:  {checks['risky_security_groups']['count']} ({checks['risky_security_groups']['severity']})")
    
    print("=" * 60)


def send_notification(findings):
    """
    Send SNS notification with findings
    
    Args:
        findings: dict containing all check results
        
    Returns:
        bool: True if notification sent successfully
    """
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
    """
    Format findings into readable email message
    
    Args:
        findings: dict containing all check results
        
    Returns:
        str: Formatted message for email notification
    """
    total = findings['total_issues']
    checks = findings['checks']
    timestamp = findings['timestamp']
    
    # Determine overall severity
    if total >= 10:
        severity = "CRITICAL"
    elif total >= 5:
        severity = "HIGH"
    elif total >= 1:
        severity = "MEDIUM"
    else:
        severity = "LOW"
    
    message = f"""
MedTech Security Compliance Report
=====================================
Generated: {timestamp}
Overall Severity: {severity}

TOTAL ISSUES FOUND: {total}
=====================================

S3 BUCKETS
----------
Public Buckets: {checks['public_s3_buckets']['count']}
{format_item_list(checks['public_s3_buckets']['items'])}

Unencrypted Buckets: {checks['unencrypted_s3_buckets']['count']}
{format_item_list(checks['unencrypted_s3_buckets']['items'])}

IAM COMPLIANCE
--------------
Users without MFA: {checks['users_without_mfa']['count']}
{format_item_list(checks['users_without_mfa']['items'])}

NETWORK SECURITY
----------------
Risky Security Groups: {checks['risky_security_groups']['count']}
{format_item_list(checks['risky_security_groups']['items'])}

=====================================
ACTION REQUIRED
=====================================
Please review these findings in the AWS Console and take appropriate action.

Priority Guidelines:
- CRITICAL issues: Address within 24 hours
- HIGH severity: Address within 1 week
- MEDIUM severity: Address within 1 month

For assistance, contact: security@medtech.com
    """
    
    return message.strip()


def format_item_list(items):
    """
    Helper function to format list items for notification
    
    Args:
        items: list of items to format
        
    Returns:
        str: Formatted string of items
    """
    if not items:
        return "  (none)"
    
    formatted = []
    for item in items:
        formatted.append(f"  - {item}")
    return "\n".join(formatted)


# For local testing
if __name__ == "__main__":
    print("Running local test...\n")
    result = lambda_handler({}, {})
    print("\n" + "=" * 60)
    print("LAMBDA RETURN VALUE:")
    print("=" * 60)
    print(json.dumps(json.loads(result['body']), indent=2, default=str))
