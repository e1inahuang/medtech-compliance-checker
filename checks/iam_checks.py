"""
IAM Security Checks
Checks for users without MFA and overly permissive policies
"""
import boto3

def check_mfa_compliance():
    """
    Check for IAM users without MFA enabled
    Returns: list of non-compliant usernames
    """
    # TODO: Person 2 implement this
    pass