"""
S3 Security Checks
Checks for public buckets and unencrypted buckets
"""
import boto3
from botocore.exceptions import ClientError


def check_public_buckets():
    """
    Check for S3 buckets with public access
    Returns: list of public bucket names
    """
    s3 = boto3.client('s3')
    public_buckets = []
    
    try:
        response = s3.list_buckets()
        buckets = response.get('Buckets', [])
        
        print(f"  [S3] Found {len(buckets)} buckets to check")
        
        for bucket in buckets:
            bucket_name = bucket['Name']
            
            try:
                acl = s3.get_bucket_acl(Bucket=bucket_name)
                
                for grant in acl.get('Grants', []):
                    grantee = grant.get('Grantee', {})
                    
                    if grantee.get('Type') == 'Group':
                        uri = grantee.get('URI', '')
                        if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                            public_buckets.append(bucket_name)
                            print(f"  [WARNING] Public bucket found: {bucket_name}")
                            break
                            
            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == 'AccessDenied':
                    print(f"  [WARNING] Access denied for bucket: {bucket_name}")
                else:
                    print(f"  [ERROR] Error checking bucket {bucket_name}: {e}")
                    
    except ClientError as e:
        print(f"[ERROR] Error listing buckets: {e}")
        
    print(f"  [S3] Public buckets check complete: {len(public_buckets)} found")
    return public_buckets


def check_unencrypted_buckets():
    """
    Check for S3 buckets without default encryption
    Returns: list of unencrypted bucket names
    """
    s3 = boto3.client('s3')
    unencrypted_buckets = []
    
    try:
        response = s3.list_buckets()
        buckets = response.get('Buckets', [])
        
        print(f"  [S3] Checking encryption for {len(buckets)} buckets")
        
        for bucket in buckets:
            bucket_name = bucket['Name']
            
            try:
                s3.get_bucket_encryption(Bucket=bucket_name)
                
            except ClientError as e:
                error_code = e.response['Error']['Code']
                
                if error_code == 'ServerSideEncryptionConfigurationNotFoundError':
                    unencrypted_buckets.append(bucket_name)
                    print(f"  [WARNING] Unencrypted bucket: {bucket_name}")
                    
                elif error_code == 'AccessDenied':
                    print(f"  [WARNING] Access denied for bucket: {bucket_name}")
                    
                else:
                    print(f"  [ERROR] Error checking encryption for {bucket_name}: {e}")
                    
    except ClientError as e:
        print(f"[ERROR] Error listing buckets: {e}")
        
    print(f"  [S3] Encryption check complete: {len(unencrypted_buckets)} unencrypted")
    return unencrypted_buckets


if __name__ == "__main__":
    print("Testing S3 checks...\n")
    
    print("Test 1: Public buckets")
    public = check_public_buckets()
    print(f"Results: {public}\n")
    
    print("Test 2: Unencrypted buckets")
    unencrypted = check_unencrypted_buckets()
    print(f"Results: {unencrypted}")
