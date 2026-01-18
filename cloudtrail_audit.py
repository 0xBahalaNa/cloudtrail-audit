"""
cloudtrail_audit.py

Analyzes AWS CloudTrail logs to detect suspicious activity.

Detections:
    1. Root Account Usage - Any API call made by the root account
    2. Failed API Calls - API calls that returned an error
    3. Sensitive API Calls - IAM, security group, and logging changes
    4. Console Logins - AWS Management Console sign-ins

How it works:
    - Uses CloudTrail's lookup_events() API to query recent events
    - Parses the CloudTrailEvent JSON for detailed information
    - Categorizes events based on event name, user identity, and error codes

Usage:
    python cloudtrail_audit.py

Configuration:
    HOURS_TO_LOOK_BACK - How far back to search (default: 24 hours)
    SENSITIVE_EVENTS - Set of API calls to flag as sensitive

Requirements:
    - boto3 installed (pip install boto3)
    - AWS credentials configured (aws configure)
    - No CloudTrail trail required (uses Event History)
"""

import boto3
import json
from datetime import datetime, timedelta, timezone

# ---------------------------------------------------------------------------
# Setup: Create CloudTrail client
# ---------------------------------------------------------------------------

cloudtrail = boto3.client('cloudtrail')

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# How far back to search (in hours)
HOURS_TO_LOOK_BACK = 24

# Sensitive API calls to flag
# These events indicate relevant security changes
SENSITIVE_EVENTS = {
    # Console access
    'ConsoleLogin',
    # IAM user management
    'CreateUser', 'DeleteUser', 'CreateAccessKey', 'DeleteAccessKey',
    # IAM policy changes
    'AttachUserPolicy', 'DetachUserPolicy', 'PutUserPolicy',
    # IAM role changes
    'CreateRole', 'DeleteRole', 'AttachRolePolicy',
    # Security group changes
    'AuthorizeSecurityGroupIngress', 'AuthorizeSecurityGroupEgress',
    'CreateSecurityGroup', 'DeleteSecurityGroup',
    # CloudTrail tampering
    'StopLogging', 'DeleteTrail', 'UpdateTrail',
    # S3 policy changes
    'PutBucketPolicy', 'DeleteBucketPolicy', 'PutBucketAcl'
}

# ---------------------------------------------------------------------------
# Calculate time range
# ---------------------------------------------------------------------------

end_time = datetime.now(timezone.utc)
start_time = end_time - timedelta(hours=HOURS_TO_LOOK_BACK)

print(f"Searching events from {start_time} to {end_time}")
print(f"(Last {HOURS_TO_LOOK_BACK} hours)\n")

# ---------------------------------------------------------------------------
# Step 1: Query CloudTrail events
# ---------------------------------------------------------------------------

# lookup_events() queries the CloudTrail Event History
# This works without a configured trail (last 90 days of management events)
response = cloudtrail.lookup_events(
    StartTime=start_time,
    EndTime=end_time,
    MaxResults=50
)

events = response['Events']

print(f"Found {len(events)} events. Analyzing for suspicious activity...\n")

# ---------------------------------------------------------------------------
# Step 2: Initialize findings lists
# ---------------------------------------------------------------------------

root_events = []       # Root account usage (critical)
failed_events = []     # API calls that failed
sensitive_events = []  # Security-relevant API calls
console_logins = []    # AWS Console sign-ins

# ---------------------------------------------------------------------------
# Step 3: Analyze each event
# ---------------------------------------------------------------------------

for event in events:
    # Basic event info from the response
    event_name = event['EventName']
    event_time = event['EventTime']
    event_source = event['EventSource']
    username = event.get('Username', 'N/A')
    
    # Parse the full CloudTrail event JSON for more details
    # This contains userIdentity, errorCode, sourceIPAddress, etc.
    cloud_trail_event = json.loads(event['CloudTrailEvent'])
    
    # --- Check 1: Root account usage ---
    # Root usage is always a concern - should use IAM users instead
    user_identity = cloud_trail_event.get('userIdentity', {})
    if user_identity.get('type') == 'Root':
        root_events.append({
            'time': event_time,
            'event': event_name,
            'source': event_source
        })
    
    # --- Check 2: Failed API calls ---
    # errorCode present means the API call failed
    # Could indicate permission issues, brute force attempts, or misconfigurations
    error_code = cloud_trail_event.get('errorCode')
    if error_code:
        failed_events.append({
            'time': event_time,
            'event': event_name,
            'error': error_code,
            'user': username
        })
    
    # --- Check 3: Sensitive API calls ---
    # These events indicate relevant security changes
    if event_name in SENSITIVE_EVENTS:
        sensitive_events.append({
            'time': event_time,
            'event': event_name,
            'source': event_source,
            'user': username
        })
    
    # --- Check 4: Console logins ---
    # Track who is logging into the AWS Console
    if event_name == 'ConsoleLogin':
        console_logins.append({
            'time': event_time,
            'user': username,
            'source_ip': cloud_trail_event.get('sourceIPAddress', 'N/A')
        })

# ---------------------------------------------------------------------------
# Step 4: Print findings
# ---------------------------------------------------------------------------

print("=" * 60)
print("SECURITY FINDINGS")
print("=" * 60)

# Root account usage (most critical)
print(f"\n[1] ROOT ACCOUNT USAGE: {len(root_events)} event(s)")
if root_events:
    for e in root_events:
        print(f"    [CRITICAL] {e['time']} | {e['event']}")

# Failed API calls
print(f"\n[2] FAILED API CALLS: {len(failed_events)} event(s)")
if failed_events:
    for e in failed_events:
        print(f"    [WARN] {e['time']} | {e['event']} | Error: {e['error']} | User: {e['user']}")

# Sensitive API calls
print(f"\n[3] SENSITIVE API CALLS: {len(sensitive_events)} event(s)")
if sensitive_events:
    for e in sensitive_events:
        print(f"    [INFO] {e['time']} | {e['event']} | User: {e['user']}")

# Console logins
print(f"\n[4] CONSOLE LOGINS: {len(console_logins)} event(s)")
if console_logins:
    for e in console_logins:
        print(f"    [INFO] {e['time']} | User: {e['user']} | IP: {e['source_ip']}")

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

print("\n" + "=" * 60)
print("SUMMARY")
print("=" * 60)
print(f"Total events analyzed: {len(events)}")
print(f"Root account events:   {len(root_events)}")
print(f"Failed API calls:      {len(failed_events)}")
print(f"Sensitive API calls:   {len(sensitive_events)}")
print(f"Console logins:        {len(console_logins)}")