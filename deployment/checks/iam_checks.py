"""
IAM Security Checks
Comprehensive IAM audit including MFA, access keys, policies, and root account
"""
import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone


def check_mfa_compliance():
    """
    Check for IAM users without MFA enabled
    Returns: list of non-compliant usernames
    """
    iam = boto3.client('iam')
    non_compliant_users = []

    try:
        users = iam.list_users().get('Users', [])
        print(f"  [IAM] Found {len(users)} users to check for MFA")

        for user in users:
            username = user['UserName']
            try:
                mfa_devices = iam.list_mfa_devices(UserName=username).get('MFADevices', [])
                if len(mfa_devices) == 0:
                    non_compliant_users.append(username)
                    print(f"  [HIGH] No MFA: {username}")
                else:
                    print(f"  [OK] MFA enabled: {username}")
            except ClientError as e:
                print(f"  [ERROR] Error checking MFA for {username}: {e}")

    except ClientError as e:
        print(f"  [ERROR] Error listing users: {e}")

    print(f"  [IAM] MFA check complete: {len(non_compliant_users)} non-compliant")
    return non_compliant_users


def check_access_key_age():
    """
    Check for access keys older than 90 days
    Returns: list of users with old access keys
    """
    iam = boto3.client('iam')
    old_keys = []

    try:
        users = iam.list_users().get('Users', [])
        print(f"  [IAM] Checking access key age for {len(users)} users")

        for user in users:
            username = user['UserName']
            try:
                keys = iam.list_access_keys(UserName=username).get('AccessKeyMetadata', [])
                for key in keys:
                    key_id = key['AccessKeyId']
                    create_date = key['CreateDate']
                    status = key['Status']
                    
                    age_days = (datetime.now(timezone.utc) - create_date).days
                    
                    if age_days > 90 and status == 'Active':
                        detail = f"{username}: {key_id} ({age_days} days old)"
                        old_keys.append(detail)
                        print(f"  [HIGH] Old access key: {detail}")
                    elif age_days > 90:
                        detail = f"{username}: {key_id} ({age_days} days old, {status})"
                        old_keys.append(detail)
                        print(f"  [MEDIUM] Old access key (inactive): {detail}")

            except ClientError as e:
                print(f"  [ERROR] Error checking keys for {username}: {e}")

    except ClientError as e:
        print(f"  [ERROR] Error listing users: {e}")

    print(f"  [IAM] Access key age check complete: {len(old_keys)} old keys found")
    return old_keys


def check_unused_access_keys():
    """
    Check for access keys that have never been used or unused for 90+ days
    Returns: list of unused access keys
    """
    iam = boto3.client('iam')
    unused_keys = []

    try:
        users = iam.list_users().get('Users', [])
        print(f"  [IAM] Checking access key usage for {len(users)} users")

        for user in users:
            username = user['UserName']
            try:
                keys = iam.list_access_keys(UserName=username).get('AccessKeyMetadata', [])
                for key in keys:
                    key_id = key['AccessKeyId']
                    status = key['Status']
                    
                    if status != 'Active':
                        continue
                    
                    last_used = iam.get_access_key_last_used(AccessKeyId=key_id)
                    last_used_info = last_used.get('AccessKeyLastUsed', {})
                    last_used_date = last_used_info.get('LastUsedDate')
                    
                    if last_used_date is None:
                        detail = f"{username}: {key_id} (never used)"
                        unused_keys.append(detail)
                        print(f"  [HIGH] Never used access key: {detail}")
                    else:
                        days_since_use = (datetime.now(timezone.utc) - last_used_date).days
                        if days_since_use > 90:
                            detail = f"{username}: {key_id} (unused for {days_since_use} days)"
                            unused_keys.append(detail)
                            print(f"  [MEDIUM] Unused access key: {detail}")

            except ClientError as e:
                print(f"  [ERROR] Error checking key usage for {username}: {e}")

    except ClientError as e:
        print(f"  [ERROR] Error listing users: {e}")

    print(f"  [IAM] Unused key check complete: {len(unused_keys)} unused keys found")
    return unused_keys


def check_admin_users():
    """
    Check for users with AdministratorAccess or overly permissive policies
    Returns: list of users with admin access
    """
    iam = boto3.client('iam')
    admin_users = []
    dangerous_policies = ['AdministratorAccess', 'PowerUserAccess', 'IAMFullAccess']

    try:
        users = iam.list_users().get('Users', [])
        print(f"  [IAM] Checking admin privileges for {len(users)} users")

        for user in users:
            username = user['UserName']
            user_policies = []

            try:
                # Check attached managed policies
                attached = iam.list_attached_user_policies(UserName=username)
                for policy in attached.get('AttachedPolicies', []):
                    policy_name = policy['PolicyName']
                    if policy_name in dangerous_policies:
                        user_policies.append(policy_name)

                # Check policies through groups
                groups = iam.list_groups_for_user(UserName=username).get('Groups', [])
                for group in groups:
                    group_policies = iam.list_attached_group_policies(GroupName=group['GroupName'])
                    for policy in group_policies.get('AttachedPolicies', []):
                        policy_name = policy['PolicyName']
                        if policy_name in dangerous_policies:
                            user_policies.append(f"{policy_name} (via {group['GroupName']})")

                if user_policies:
                    detail = f"{username}: {', '.join(user_policies)}"
                    admin_users.append(detail)
                    print(f"  [CRITICAL] Admin user: {detail}")

            except ClientError as e:
                print(f"  [ERROR] Error checking policies for {username}: {e}")

    except ClientError as e:
        print(f"  [ERROR] Error listing users: {e}")

    print(f"  [IAM] Admin user check complete: {len(admin_users)} admin users found")
    return admin_users


def check_inactive_users():
    """
    Check for users who haven't logged in for 90+ days
    Returns: list of inactive users
    """
    iam = boto3.client('iam')
    inactive_users = []

    try:
        users = iam.list_users().get('Users', [])
        print(f"  [IAM] Checking user activity for {len(users)} users")

        for user in users:
            username = user['UserName']
            password_last_used = user.get('PasswordLastUsed')

            if password_last_used:
                days_inactive = (datetime.now(timezone.utc) - password_last_used).days
                if days_inactive > 90:
                    detail = f"{username}: {days_inactive} days since last login"
                    inactive_users.append(detail)
                    print(f"  [MEDIUM] Inactive user: {detail}")
            else:
                # Check if user has console access but never logged in
                try:
                    iam.get_login_profile(UserName=username)
                    detail = f"{username}: has console access but never logged in"
                    inactive_users.append(detail)
                    print(f"  [MEDIUM] Never logged in: {detail}")
                except ClientError as e:
                    if e.response['Error']['Code'] != 'NoSuchEntity':
                        print(f"  [ERROR] Error checking login profile for {username}: {e}")

    except ClientError as e:
        print(f"  [ERROR] Error listing users: {e}")

    print(f"  [IAM] Inactive user check complete: {len(inactive_users)} inactive users found")
    return inactive_users


def check_root_account():
    """
    Check root account security status
    Returns: list of root account issues
    """
    iam = boto3.client('iam')
    root_issues = []

    try:
        summary = iam.get_account_summary().get('SummaryMap', {})

        # Check root MFA
        if summary.get('AccountMFAEnabled', 0) == 0:
            root_issues.append("Root account MFA not enabled")
            print("  [CRITICAL] Root account MFA not enabled")
        else:
            print("  [OK] Root account MFA enabled")

        # Check root access keys
        try:
            credential_report = iam.generate_credential_report()
            if credential_report['State'] == 'COMPLETE':
                report = iam.get_credential_report()
                import csv
                from io import StringIO
                reader = csv.DictReader(StringIO(report['Content'].decode('utf-8')))
                for row in reader:
                    if row['user'] == '<root_account>':
                        if row.get('access_key_1_active', 'false') == 'true':
                            root_issues.append("Root account has active access key 1")
                            print("  [CRITICAL] Root account has active access key")
                        if row.get('access_key_2_active', 'false') == 'true':
                            root_issues.append("Root account has active access key 2")
                            print("  [CRITICAL] Root account has second active access key")
        except ClientError as e:
            print(f"  [WARNING] Could not check root access keys: {e}")

    except ClientError as e:
        print(f"  [ERROR] Error checking root account: {e}")

    print(f"  [IAM] Root account check complete: {len(root_issues)} issues found")
    return root_issues


if __name__ == "__main__":
    print("Testing IAM checks...\n")

    print("Test 1: MFA compliance")
    mfa_results = check_mfa_compliance()
    print(f"Results: {mfa_results}\n")

    print("Test 2: Access key age")
    key_age_results = check_access_key_age()
    print(f"Results: {key_age_results}\n")

    print("Test 3: Unused access keys")
    unused_results = check_unused_access_keys()
    print(f"Results: {unused_results}\n")

    print("Test 4: Admin users")
    admin_results = check_admin_users()
    print(f"Results: {admin_results}\n")

    print("Test 5: Inactive users")
    inactive_results = check_inactive_users()
    print(f"Results: {inactive_results}\n")

    print("Test 6: Root account")
    root_results = check_root_account()
    print(f"Results: {root_results}\n")