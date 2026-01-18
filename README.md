# cloudtrail_audit.py

A Python tool that analyzes AWS CloudTrail logs to detect suspicious activity.

## Overview

This lesson builds two scripts:
1. **`cloudtrail_audit.py`** - Analyzes CloudTrail events for security-relevant activity
2. **`generate_test_events.py`** - Creates test events to verify detection

## Requirements

- Python 3.x
- `boto3` library
- AWS CLI configured with credentials (`aws configure`)

### Install dependencies
```bash
pip install boto3
```

## Usage

### Run the audit
```bash
python cloudtrail_audit.py
```

**Sample output:**
```
Searching events from 2026-01-15 20:32:48+00:00 to 2026-01-16 20:32:48+00:00
(Last 24 hours)

Found 50 events. Analyzing for suspicious activity...

============================================================
SECURITY FINDINGS
============================================================

[1] ROOT ACCOUNT USAGE: 0 event(s)

[2] FAILED API CALLS: 0 event(s)

[3] SENSITIVE API CALLS: 3 event(s)
    [INFO] 2026-01-16 12:19:51 | AuthorizeSecurityGroupIngress | User: aws-grc-engineering-admin
    [INFO] 2026-01-16 12:19:51 | DeleteSecurityGroup | User: aws-grc-engineering-admin
    [INFO] 2026-01-16 12:19:50 | CreateSecurityGroup | User: aws-grc-engineering-admin

[4] CONSOLE LOGINS: 0 event(s)

============================================================
SUMMARY
============================================================
Total events analyzed: 50
Root account events:   0
Failed API calls:      0
Sensitive API calls:   3
Console logins:        0
```

### Generate test events (optional)
```bash
python generate_test_events.py
# Wait 5-15 minutes for CloudTrail to log events
python cloudtrail_audit.py
```

## Detection Categories

| Category | Description | Severity |
|----------|-------------|----------|
| **Root Account Usage** | Any API call made by root account | CRITICAL |
| **Failed API Calls** | API calls that returned an error | WARN |
| **Sensitive API Calls** | IAM, security group, logging changes | INFO |
| **Console Logins** | AWS Management Console sign-ins | INFO |

## Sensitive Events Monitored

### IAM Events
- `CreateUser`, `DeleteUser`
- `CreateAccessKey`, `DeleteAccessKey`
- `AttachUserPolicy`, `DetachUserPolicy`, `PutUserPolicy`
- `CreateRole`, `DeleteRole`, `AttachRolePolicy`

### EC2 Security Group Events
- `CreateSecurityGroup`, `DeleteSecurityGroup`
- `AuthorizeSecurityGroupIngress`, `AuthorizeSecurityGroupEgress`

### CloudTrail Events
- `StopLogging`, `DeleteTrail`, `UpdateTrail`

### S3 Events
- `PutBucketPolicy`, `DeleteBucketPolicy`, `PutBucketAcl`

## Configuration

Edit these variables in `cloudtrail_audit.py`:

```python
# How far back to search (in hours)
HOURS_TO_LOOK_BACK = 24

# Add/remove events to monitor
SENSITIVE_EVENTS = {
    'ConsoleLogin',
    'CreateUser',
    # ...
}
```

## Key Concepts Learned

| Concept | Description |
|---------|-------------|
| `cloudtrail.lookup_events()` | Query CloudTrail Event History |
| `datetime` module | Calculate time ranges |
| `json.loads()` | Parse JSON strings |
| `timedelta` | Represent time differences |
| Nested JSON parsing | Extract data from complex structures |

---

## GRC Application

This tool supports:
- **CIS AWS Benchmark** - 3.1-3.14 (CloudTrail monitoring)
- **SOC 2** - CC6.1 (Logical Access Controls)
- **NIST 800-53** - AU-2, AU-3 (Audit Events)
- **PCI DSS** - 10.2 (Audit Trail)

## Future Enhancements

- Add pagination for more events (NextToken)
- Export findings to CSV/JSON
- Email alerts for critical findings
- Filter by user or IP address
- Command-line arguments (argparse)
- Detect specific attack patterns

