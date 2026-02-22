"""
generate_test_events.py

Generates test CloudTrail events by performing detectable AWS actions.
Run this script, then run cloudtrail_audit.py to verify detection.

Events Generated:
    1. CreateSecurityGroup - Creates a temporary security group
    2. AuthorizeSecurityGroupIngress - Adds an SSH rule
    3. DeleteSecurityGroup - Deletes the security group
    4. CreateUser (failed) - Attempts to create existing user

Note: CloudTrail events can take 5-15 minutes to appear in Event History.

Usage:
    python generate_test_events.py
    # Wait 5-15 minutes
    python cloudtrail_audit.py

Requirements:
    - boto3 installed (pip install boto3)
    - AWS credentials configured (aws configure)
"""

import boto3

# ---------------------------------------------------------------------------
# Setup: Create AWS clients
# ---------------------------------------------------------------------------

ec2 = boto3.client('ec2')
iam = boto3.client('iam')

print("Generating test CloudTrail events...\n")

# ---------------------------------------------------------------------------
# Test 1: Security group operations (sensitive API calls)
# ---------------------------------------------------------------------------

print("[1] Creating test security group...")
try:
    # Get default VPC (security groups require a VPC)
    vpcs = ec2.describe_vpcs(Filters=[{'Name': 'is-default', 'Values': ['true']}])
    vpc_id = vpcs['Vpcs'][0]['VpcId']
    
    # Create security group (triggers CreateSecurityGroup event)
    response = ec2.create_security_group(
        GroupName='cloudtrail-test-sg',
        Description='Temporary SG for CloudTrail testing',
        VpcId=vpc_id
    )
    sg_id = response['GroupId']
    print(f"    Created: cloudtrail-test-sg ({sg_id})")
    
    # Add an inbound rule (triggers AuthorizeSecurityGroupIngress event)
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpProtocol='tcp',
        FromPort=22,
        ToPort=22,
        CidrIp='0.0.0.0/0'
    )
    print("    Added SSH rule (AuthorizeSecurityGroupIngress)")
    
    # Delete the security group (triggers DeleteSecurityGroup event)
    ec2.delete_security_group(GroupId=sg_id)
    print(f"    Deleted: cloudtrail-test-sg")
    
except Exception as e:
    print(f"    Error: {e}")

# ---------------------------------------------------------------------------
# Test 2: Failed IAM operation (error event)
# ---------------------------------------------------------------------------

print("\n[2] Attempting to create existing IAM user (will fail)...")
try:
    # This will fail because the user already exists
    # Triggers CreateUser event with errorCode
    iam.create_user(UserName='aws-grc-engineering-admin')
    print("    Created user (unexpected)")
except iam.exceptions.EntityAlreadyExistsException:
    print("    [Expected] EntityAlreadyExists error triggered")
except Exception as e:
    print(f"    Error: {e}")

# ---------------------------------------------------------------------------
# Test 3: Normal activity (no alert expected)
# ---------------------------------------------------------------------------

print("\n[3] Listing IAM users (normal activity)...")
users = iam.list_users()
print(f"    Found {len(users['Users'])} users")

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

print("\n" + "=" * 50)
print("Test events generated!")
print("Wait 5-15 minutes, then run: python cloudtrail_audit.py")
print("=" * 50)
