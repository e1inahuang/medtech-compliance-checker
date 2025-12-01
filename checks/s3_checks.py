"""
S3 Security Checks
Comprehensive S3 bucket security audit
"""
import boto3
from botocore.exceptions import ClientError
import json


def check_public_buckets():
    """
    Check for S3 buckets with public access via ACL
    Returns: list of public bucket names
    """
    s3 = boto3.client('s3')
    public_buckets = []

    try:
        buckets = s3.list_buckets().get('Buckets', [])
        print(f"  [S3] Found {len(buckets)} buckets to check for public access")

        for bucket in buckets:
            bucket_name = bucket['Name']
            try:
                acl = s3.get_bucket_acl(Bucket=bucket_name)
                for grant in acl.get('Grants', []):
                    grantee = grant.get('Grantee', {})
                    if grantee.get('Type') == 'Group':
                        uri = grantee.get('URI', '')
                        if 'AllUsers' in uri:
                            public_buckets.append(f"{bucket_name} (Public via ACL - AllUsers)")
                            print(f"  [CRITICAL] Public bucket (AllUsers): {bucket_name}")
                            break
                        elif 'AuthenticatedUsers' in uri:
                            public_buckets.append(f"{bucket_name} (Public via ACL - AuthenticatedUsers)")
                            print(f"  [HIGH] Public bucket (AuthenticatedUsers): {bucket_name}")
                            break

            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == 'AccessDenied':
                    print(f"  [WARNING] Access denied for bucket: {bucket_name}")
                else:
                    print(f"  [ERROR] Error checking bucket {bucket_name}: {e}")

    except ClientError as e:
        print(f"  [ERROR] Error listing buckets: {e}")

    print(f"  [S3] Public bucket check complete: {len(public_buckets)} found")
    return public_buckets


def check_public_bucket_policy():
    """
    Check for S3 buckets with public bucket policies
    Returns: list of buckets with public policies
    """
    s3 = boto3.client('s3')
    public_policy_buckets = []

    try:
        buckets = s3.list_buckets().get('Buckets', [])
        print(f"  [S3] Checking bucket policies for {len(buckets)} buckets")

        for bucket in buckets:
            bucket_name = bucket['Name']
            try:
                policy = s3.get_bucket_policy(Bucket=bucket_name)
                policy_doc = json.loads(policy['Policy'])

                for statement in policy_doc.get('Statement', []):
                    principal = statement.get('Principal', {})
                    effect = statement.get('Effect', '')

                    # Check for public access
                    if effect == 'Allow':
                        if principal == '*' or principal == {"AWS": "*"}:
                            condition = statement.get('Condition', {})
                            if not condition:  # No condition means fully public
                                public_policy_buckets.append(f"{bucket_name} (Public policy - Principal: *)")
                                print(f"  [CRITICAL] Public bucket policy: {bucket_name}")
                                break

            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == 'NoSuchBucketPolicy':
                    pass  # No policy is fine
                elif error_code == 'AccessDenied':
                    print(f"  [WARNING] Access denied for bucket policy: {bucket_name}")
                else:
                    print(f"  [ERROR] Error checking bucket policy {bucket_name}: {e}")

    except ClientError as e:
        print(f"  [ERROR] Error listing buckets: {e}")

    print(f"  [S3] Bucket policy check complete: {len(public_policy_buckets)} public policies found")
    return public_policy_buckets


def check_unencrypted_buckets():
    """
    Check for S3 buckets without default encryption
    Returns: list of unencrypted bucket names
    """
    s3 = boto3.client('s3')
    unencrypted_buckets = []

    try:
        buckets = s3.list_buckets().get('Buckets', [])
        print(f"  [S3] Checking encryption for {len(buckets)} buckets")

        for bucket in buckets:
            bucket_name = bucket['Name']
            try:
                s3.get_bucket_encryption(Bucket=bucket_name)
            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == 'ServerSideEncryptionConfigurationNotFoundError':
                    unencrypted_buckets.append(bucket_name)
                    print(f"  [HIGH] Unencrypted bucket: {bucket_name}")
                elif error_code == 'AccessDenied':
                    print(f"  [WARNING] Access denied for bucket: {bucket_name}")
                else:
                    print(f"  [ERROR] Error checking encryption for {bucket_name}: {e}")

    except ClientError as e:
        print(f"  [ERROR] Error listing buckets: {e}")

    print(f"  [S3] Encryption check complete: {len(unencrypted_buckets)} unencrypted")
    return unencrypted_buckets


def check_bucket_versioning():
    """
    Check for S3 buckets without versioning enabled
    Returns: list of buckets without versioning
    """
    s3 = boto3.client('s3')
    no_versioning = []

    try:
        buckets = s3.list_buckets().get('Buckets', [])
        print(f"  [S3] Checking versioning for {len(buckets)} buckets")

        for bucket in buckets:
            bucket_name = bucket['Name']
            try:
                versioning = s3.get_bucket_versioning(Bucket=bucket_name)
                status = versioning.get('Status', 'Disabled')

                if status != 'Enabled':
                    no_versioning.append(f"{bucket_name} (Status: {status})")
                    print(f"  [MEDIUM] No versioning: {bucket_name}")

            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == 'AccessDenied':
                    print(f"  [WARNING] Access denied for bucket: {bucket_name}")
                else:
                    print(f"  [ERROR] Error checking versioning for {bucket_name}: {e}")

    except ClientError as e:
        print(f"  [ERROR] Error listing buckets: {e}")

    print(f"  [S3] Versioning check complete: {len(no_versioning)} without versioning")
    return no_versioning


def check_bucket_logging():
    """
    Check for S3 buckets without access logging enabled
    Returns: list of buckets without logging
    """
    s3 = boto3.client('s3')
    no_logging = []

    try:
        buckets = s3.list_buckets().get('Buckets', [])
        print(f"  [S3] Checking logging for {len(buckets)} buckets")

        for bucket in buckets:
            bucket_name = bucket['Name']
            try:
                logging = s3.get_bucket_logging(Bucket=bucket_name)
                if 'LoggingEnabled' not in logging:
                    no_logging.append(bucket_name)
                    print(f"  [LOW] No logging: {bucket_name}")

            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == 'AccessDenied':
                    print(f"  [WARNING] Access denied for bucket: {bucket_name}")
                else:
                    print(f"  [ERROR] Error checking logging for {bucket_name}: {e}")

    except ClientError as e:
        print(f"  [ERROR] Error listing buckets: {e}")

    print(f"  [S3] Logging check complete: {len(no_logging)} without logging")
    return no_logging


if __name__ == "__main__":
    print("Testing S3 checks...\n")

    print("Test 1: Public buckets (ACL)")
    public = check_public_buckets()
    print(f"Results: {public}\n")

    print("Test 2: Public bucket policies")
    public_policy = check_public_bucket_policy()
    print(f"Results: {public_policy}\n")

    print("Test 3: Unencrypted buckets")
    unencrypted = check_unencrypted_buckets()
    print(f"Results: {unencrypted}\n")

    print("Test 4: Bucket versioning")
    versioning = check_bucket_versioning()
    print(f"Results: {versioning}\n")

    print("Test 5: Bucket logging")
    logging = check_bucket_logging()
    print(f"Results: {logging}\n")