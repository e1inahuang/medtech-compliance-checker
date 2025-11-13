"""
EC2/Network Security Checks
Checks for overly permissive security groups
"""
import boto3

def check_security_groups():
    """
    Check for security groups allowing 0.0.0.0/0 access
    Returns: list of risky security group IDs
    """
    # TODO: Person 3 implement this
    pass