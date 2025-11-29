"""
IAM Security Checks
Checks for users without MFA
"""
import boto3
from botocore.exceptions import ClientError


def check_mfa_compliance():
    """
    Check for IAM users without MFA enabled
    Returns: list of non-compliant usernames
    """
    iam = boto3.client('iam')
    non_compliant_users = []
    
    try:
        response = iam.list_users()
        users = response.get('Users', [])
        
        print(f"  [IAM] Found {len(users)} users to check")
        
        for user in users:
            username = user['UserName']
            
            try:
                mfa_response = iam.list_mfa_devices(UserName=username)
                mfa_devices = mfa_response.get('MFADevices', [])
                
                if len(mfa_devices) == 0:
                    non_compliant_users.append(username)
                    print(f"  [WARNING] No MFA: {username}")
                else:
                    print(f"  [OK] MFA enabled: {username}")
                    
            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == 'AccessDenied':
                    print(f"  [WARNING] Access denied for user: {username}")
                else:
                    print(f"  [ERROR] Error checking user {username}: {e}")
                    
    except ClientError as e:
        print(f"[ERROR] Error listing users: {e}")
        
    print(f"  [IAM] MFA check complete: {len(non_compliant_users)} non-compliant")
    return non_compliant_users


if __name__ == "__main__":
    print("Testing IAM checks...\n")
    
    print("Test: MFA compliance")
    results = check_mfa_compliance()
    print(f"\nResults: {results}")
    print(f"Total users without MFA: {len(results)}")
