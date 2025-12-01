"""
EC2/Network Security Checks
Enhanced multi-region scanner with severity classification
"""
import boto3
from botocore.exceptions import ClientError


# Severity classification by port
CRITICAL_PORTS = {22, 3389, 3306, 5432, 1433, 6379, 27017}  # SSH, RDP, databases
HIGH_PORTS = {21, 23, 25, 110, 135, 139, 445}  # FTP, Telnet, SMTP, SMB
MEDIUM_PORTS = {8080, 8443, 9000, 5601}  # Admin interfaces
IGNORE_PORTS = {80, 443}  # Standard web ports, usually OK


def classify_port_severity(port):
    """Classify severity based on port number"""
    if port in CRITICAL_PORTS:
        return "CRITICAL"
    if port in HIGH_PORTS:
        return "HIGH"
    if port in MEDIUM_PORTS:
        return "MEDIUM"
    return "LOW"


def format_rule(region, sg_id, sg_name, direction, ip_version,
                proto, port_range, source, severity, in_use, attached):
    """Format rule output in unified format"""
    return (
        f"[{region}] {sg_id} ({sg_name}): "
        f"[{direction}][{ip_version}] {proto} {port_range} from {source} "
        f"[{severity}], in_use={in_use}, attached={attached}"
    )


def check_security_groups():
    """
    Multi-region security group scanner
    Checks for overly permissive inbound and outbound rules
    Returns: list of risky rules with details
    """
    risky_rules = []
    regions = ["us-east-1", "us-east-2", "us-west-1", "us-west-2"]
    
    print(f"  [EC2] Scanning AWS regions: {regions}")

    for region_name in regions:
        print(f"\n  [EC2][{region_name}] Starting scan...")
        ec2 = boto3.client("ec2", region_name=region_name)

        # Get SG usage mapping from EC2 instances
        sg_usage = {}
        try:
            reservations = ec2.describe_instances().get("Reservations", [])
            for res in reservations:
                for inst in res.get("Instances", []):
                    inst_id = inst["InstanceId"]
                    inst_name = next(
                        (t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"),
                        "(no-name)"
                    )
                    inst_label = f"{inst_id} ({inst_name})"
                    for sg in inst.get("SecurityGroups", []):
                        sg_id = sg["GroupId"]
                        sg_usage.setdefault(sg_id, []).append(inst_label)
        except ClientError as e:
            print(f"  [EC2][{region_name}] Unable to list instances: {e}")
            continue

        used_sg_ids = set(sg_usage.keys())

        # Get all security groups
        try:
            all_sgs = ec2.describe_security_groups().get("SecurityGroups", [])
        except ClientError as e:
            print(f"  [EC2][{region_name}] Error listing security groups: {e}")
            continue

        total_sg = len(all_sgs)
        unused_sg_ids = set(sg["GroupId"] for sg in all_sgs) - used_sg_ids

        print(f"  [EC2][{region_name}] Total Security Groups: {total_sg}")
        print(f"  [EC2][{region_name}]   In Use: {len(used_sg_ids)}")
        print(f"  [EC2][{region_name}]   Unused: {len(unused_sg_ids)}")

        # Scan each security group
        for sg in all_sgs:
            sg_id = sg["GroupId"]
            sg_name = sg["GroupName"]
            is_in_use = sg_id in used_sg_ids
            attached = sg_usage.get(sg_id, ["(no EC2)"])

            # Check INBOUND rules
            for rule in sg.get("IpPermissions", []):
                proto = rule.get("IpProtocol", "all")
                from_port = rule.get("FromPort")
                to_port = rule.get("ToPort")

                # ALL TRAFFIC rule (-1 protocol)
                if proto == "-1":
                    for ip_range in rule.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            detail = format_rule(
                                region_name, sg_id, sg_name,
                                "INBOUND", "IPv4", "all", "ALL",
                                "0.0.0.0/0", "CRITICAL", is_in_use, attached
                            )
                            risky_rules.append(detail)
                            print(f"  [CRITICAL] {detail}")
                    for ip_range in rule.get("Ipv6Ranges", []):
                        if ip_range.get("CidrIpv6") == "::/0":
                            detail = format_rule(
                                region_name, sg_id, sg_name,
                                "INBOUND", "IPv6", "all", "ALL",
                                "::/0", "CRITICAL", is_in_use, attached
                            )
                            risky_rules.append(detail)
                            print(f"  [CRITICAL] {detail}")
                    continue

                # Skip standard web ports
                if from_port in IGNORE_PORTS:
                    continue

                port_range = f"{from_port}-{to_port}" if from_port != to_port else str(from_port)

                # Check IPv4 0.0.0.0/0
                for ip_range in rule.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        severity = classify_port_severity(from_port)
                        detail = format_rule(
                            region_name, sg_id, sg_name,
                            "INBOUND", "IPv4", proto, port_range,
                            "0.0.0.0/0", severity, is_in_use, attached
                        )
                        risky_rules.append(detail)
                        print(f"  [{severity}] {detail}")

                # Check IPv6 ::/0
                for ip_range in rule.get("Ipv6Ranges", []):
                    if ip_range.get("CidrIpv6") == "::/0":
                        severity = classify_port_severity(from_port)
                        detail = format_rule(
                            region_name, sg_id, sg_name,
                            "INBOUND", "IPv6", proto, port_range,
                            "::/0", severity, is_in_use, attached
                        )
                        risky_rules.append(detail)
                        print(f"  [{severity}] {detail}")

            # Check OUTBOUND rules
            for rule in sg.get("IpPermissionsEgress", []):
                proto = rule.get("IpProtocol", "all")
                from_port = rule.get("FromPort")
                to_port = rule.get("ToPort")

                # ALL TRAFFIC outbound to 0.0.0.0/0
                if proto == "-1":
                    for ip_range in rule.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            detail = format_rule(
                                region_name, sg_id, sg_name,
                                "OUTBOUND", "IPv4", "all", "ALL",
                                "0.0.0.0/0", "MEDIUM", is_in_use, attached
                            )
                            risky_rules.append(detail)
                            print(f"  [MEDIUM] {detail}")

    print(f"\n  [EC2] Multi-region scan complete: {len(risky_rules)} risky rules found")
    return risky_rules


if __name__ == "__main__":
    print("Testing EC2/Security Group checks...\n")
    results = check_security_groups()
    print(f"\nTotal risky rules: {len(results)}")