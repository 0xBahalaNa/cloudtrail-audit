![License](https://img.shields.io/badge/License-MIT-green?style=flat)
![Python](https://img.shields.io/badge/Python-3.11%2B-3776ab?style=flat)
![AWS](https://img.shields.io/badge/AWS-CloudTrail-FF9900?style=flat&logo=amazonwebservices)
![NIST 800-53](https://img.shields.io/badge/NIST-800--53%20Rev%205-004990?style=flat)
![FedRAMP](https://img.shields.io/badge/FedRAMP-High%20Baseline-0071bc?style=flat)
![CJIS](https://img.shields.io/badge/CJIS-Security%20Policy%20v6.0-cc0000?style=flat)

# CloudTrail Audit

A Python tool that analyzes AWS CloudTrail logs to detect suspicious activity — root account usage, failed API calls, sensitive IAM / SG / Trail / S3 changes, and console logins. Built for GRC engineers, compliance analysts, and assessors working in FedRAMP High and CJIS v6.0 environments where the AU-6 weekly audit-record review is a binding obligation.

## Compliance Controls Addressed

| NIST 800-53 Rev 5 | FedRAMP High | CJIS v6.0 | Validation Method |
|--------------------|:------------:|:---------:|-------------------|
| AU-2 Event Logging | Yes | — | Consumes the CloudTrail event stream produced by AU-2 logging |
| AU-3 Content of Audit Records | Yes | — | Extracts who / what / when / source from each event |
| AU-6 Audit Record Review | Yes | 1-year retention, weekly review | Primary use case — root, failed, sensitive, console-login categories |
| AU-12 Audit Record Generation | Yes | — | Flags `StopLogging` / `DeleteTrail` / `UpdateTrail` events |
| SI-4 System Monitoring | Yes | — | Anomaly detection on the CloudTrail stream |
| IA-2 Identification and Authentication | Yes | — | Root account usage detection |

## Overview

Two scripts:

1. **`cloudtrail_audit.py`** — Analyzes CloudTrail events for security-relevant activity.
2. **`generate_test_events.py`** — Creates test events to verify detection.

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

| Category | Description | Severity | Controls |
|----------|-------------|----------|----------|
| **Root Account Usage** | Any API call made by root account | CRITICAL | IA-2, AU-6, SI-4 |
| **Failed API Calls** | API calls that returned an error | WARN | AU-6, SI-4 |
| **Sensitive API Calls** | IAM, security group, logging, S3 policy changes | INFO | AU-6, AU-12, SI-4 |
| **Console Logins** | AWS Management Console sign-ins | INFO | AU-6, IA-2 |

## Sensitive Events Monitored

### IAM Events (AC-2, AC-6)
- `CreateUser`, `DeleteUser`
- `CreateAccessKey`, `DeleteAccessKey`
- `AttachUserPolicy`, `DetachUserPolicy`, `PutUserPolicy`
- `CreateRole`, `DeleteRole`, `AttachRolePolicy`

### EC2 Security Group Events (SC-7, CM-7)
- `CreateSecurityGroup`, `DeleteSecurityGroup`
- `AuthorizeSecurityGroupIngress`, `AuthorizeSecurityGroupEgress`

### CloudTrail Events (AU-12)
- `StopLogging`, `DeleteTrail`, `UpdateTrail` — direct attacks on the audit infrastructure itself

### S3 Events (AC-3, AC-21, SC-28)
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

## How an Auditor Uses This Output

An assessor reviewing a FedRAMP High or CJIS v6.0 authorization package can use this script as the operational tool that satisfies AU-6 (Audit Record Review). The four detection categories map one-to-one to the high-leverage review questions an assessor asks during a walkthrough: *"Show me your root account monitoring,"* *"Show me your failed-API trend,"* *"Show me how you flag changes to the audit infrastructure itself,"* and *"Show me console login review."* The `SUMMARY` block becomes the per-period review record that documents AU-6 compliance, and the structured event excerpts give the assessor the raw evidence behind each finding.

## FedRAMP 20x Alignment

This script supports FedRAMP 20x compliance-as-code by producing deterministic, repeatable AU-6 review output that can feed continuous monitoring pipelines. The detection categories map cleanly to KSI metrics for CloudTrail health (root usage rate, failed-call rate, sensitive-API rate), and the per-event findings can be transformed into OSCAL Assessment Results entries. A future enhancement (see issues) adds JSON output with control IDs per finding so the script integrates directly with `evidence-logger` and OSCAL-based tooling without manual transformation.

## CJIS v6.0 Relevance

CJIS v6.0 (audit standard from April 1, 2026) introduces a hard delta on **AU-6**: agencies handling CJI must retain audit records for **1 year** and conduct **weekly review** of those records. This script is the operational tool that *performs* that weekly review. Combined with S3 archival of CloudTrail logs (Object Lock, 1-year retention) and `evidence-logger` (timestamped review records), the workflow satisfies the AU-6 delta end-to-end. A future enhancement will add a `--weekly-review` flag that produces a structured review record directly suitable for ingestion by `evidence-logger`.

## Roadmap

This tool will be consolidated into the **Unified Evidence Collector** (Project 4, Month 7), which aggregates `s3-audit`, `sg-audit`, `cloudtrail-audit`, and `evidence-logger` into a single pipeline producing OSCAL-ready evidence records. The `--weekly-review` flag noted in *CJIS v6.0 Relevance*, JSON output with per-finding control IDs, and the `evidence-logger` cross-link all land as part of that consolidation — making this tool the AU-6 review surface feeding [`oscal-evidence-pipeline`](https://github.com/0xBahalaNa/oscal-evidence-pipeline).

## Future Enhancements

- Add pagination for more events (NextToken)
- Export findings to CSV / JSON for OSCAL pipelines
- Email / SNS alerts for CRITICAL findings (root usage, trail tampering)
- Filter by user, IP address, or source ARN
- Command-line arguments (argparse) for time range, suite selection
- Detect specific attack patterns (impossible-travel, privilege escalation chains)
- `--weekly-review` flag emitting structured review records (CJIS AU-6 delta)

## Framework Reference

Control family mappings and AWS implementation details are documented in [nist-800-53-rev-5-to-aws-mapping](https://github.com/0xBahalaNa/nist-800-53-rev-5-to-aws-mapping).

## License

MIT
