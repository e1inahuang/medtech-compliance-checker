"""
EC2/Network Security Checks
Checks for overly permissive security groups
"""
import boto3
from botocore.exceptions import ClientError


def check_security_groups():
    """
    Check for security groups allowing 0.0.0.0/0 access
    Returns: list of risky security group IDs with details
    """
    ec2 = boto3.client('ec2')
    risky_groups = []
    
    try:
        response = ec2.describe_security_groups()
        security_groups = response.get('SecurityGroups', [])
        
        print(f"  [EC2] Found {len(security_groups)} security groups to check")
        
        for sg in security_groups:
            group_id = sg['GroupId']
            group_name = sg['GroupName']
            
            for rule in sg.get('IpPermissions', []):
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        from_port = rule.get('FromPort', 'All')
                        to_port = rule.get('ToPort', 'All')
                        protocol = rule.get('IpProtocol', 'All')
                        
                        risk_detail = f"{group_id} ({group_name}): Port {from_port}-{to_port}, Protocol {protocol}"
                        risky_groups.append(risk_detail)
                        print(f"  [WARNING] Risky rule: {risk_detail}")
                        break
                        
                for ipv6_range in rule.get('Ipv6Ranges', []):
                    if ipv6_range.get('CidrIpv6') == '::/0':
                        from_port = rule.get('FromPort', 'All')
                        to_port = rule.get('ToPort', 'All')
                        protocol = rule.get('IpProtocol', 'All')
                        
                        risk_detail = f"{group_id} ({group_name}): Port {from_port}-{to_port}, Protocol {protocol} [IPv6]"
                        risky_groups.append(risk_detail)
                        print(f"  [WARNING] Risky rule (IPv6): {risk_detail}")
                        break
                        
    except ClientError as e:
        print(f"[ERROR] Error checking security groups: {e}")
        
    print(f"  [EC2] Security group check complete: {len(risky_groups)} risky rules found")
    return risky_groups


if __name__ == "__main__":
    print("Testing EC2/Security Group checks...\n")
    
    print("Test: Risky security groups")
    results = check_security_groups()
    print(f"\nResults:")
    for result in results:
        print(f"  - {result}")
    print(f"\nTotal risky rules: {len(results)}")
