# AWS cloud detection lab

An AWS detection engineering lab for Stratus Red Team emulation, CloudTrail telemetry, and portable Sigma detections.

- Learn how to spot harmful AWS account changes before they cause damage
- Test detections against safe examples of actions that can look like normal administrator work
- Use CloudTrail records to write and test each detection rule
- Keep the rules in one source format that converts for Splunk and Sentinel
- Make the work repeatable so someone else can check the evidence and the tests

## Current scope

The repository contains five Stratus Red Team detections.

Each detection has a hand-authored Sigma rule, sanitized true-positive and true-negative CloudTrail fixtures, and expected Splunk SPL and Sentinel KQL output.

GitHub Actions CI runs the following checks:

- Sigma validation
- KQL and SPL conversion
- Comparison against the expected query files
- Fixture evaluation for each generated query
- Checkov and Trivy scans of committed Terraform, with successful results uploaded to GitHub Code Scanning as SARIF

## Workflow

1. Provision the AWS lab infrastructure with Terraform.
2. Detonate a Stratus Red Team technique in the lab account.
3. Query the CloudTrail events in Athena.
4. Write and tag a Sigma rule for the observed behavior.
5. Convert the rule with `sigma-cli` and the shared backend pipeline.
6. Add a `pipeline.yml` when a conversion needs values that differ by rule or environment.
7. Record benign activity in the baseline files and test the rule against the event fixtures.

## Detections

| Detection | Stratus technique | Tactic |
|---|---|---|
| AWS IAM User Console Login Without MFA | `aws.initial-access.console-login-without-mfa` | Initial Access |
| AWS Execute Commands on SageMaker Notebook Instance Through Lifecycle Configuration | `aws.execution.sagemaker-update-lifecycle-config` | Execution |
| AWS IAM Access Key Created for Another Principal | `aws.persistence.iam-backdoor-user` | Persistence |
| AWS IAM Update User Login Profile | `aws.privilege-escalation.iam-update-user-login-profile` | Privilege Escalation |
| AWS CloudTrail S3 Bucket Logging Lifecycle Change | `aws.defense-evasion.cloudtrail-lifecycle-rule` | Defense Impairment |

## Pipelines

The files under `core_pipelines/` map CloudTrail fields to the target backend.
A detection can add its own `pipeline.yml` when it needs values that differ by rule or environment.

## Repository layout

```text
.
├── .github/
│   └── workflows/
│       └── ci.yml                 # automated checks
├── terraform/                     # cloud setup files
├── core_pipelines/
│   ├── kql_pipe.yml               # Sentinel field and table mappings
│   └── spl_pipe.yml               # Splunk index and sourcetype mappings
├── detections/                    # one folder per emulated technique
│   └── <name>/
│       ├── rule.yml               # hand-authored Sigma source
│       ├── pipeline.yml           # optional rule-specific conversion values
│       └── test/
│           ├── true-positive.json
│           └── true-negative.json
├── expected/
│   ├── kusto/                     # expected Sentinel KQL conversions
│   └── splunk/                    # expected Splunk SPL conversions
├── baseline/
│   ├── benign-referencelist.yaml
│   ├── benign-suppresslist.yaml
│   └── overlap.yaml
├── attack-coverage/               # reserved for ATT&CK Navigator layers
├── docs/                          # reserved for technique write-ups
├── reports/                       # reserved for detonation reports
└── scripts/
    ├── evaluate_query_fixtures.py # evaluates converted queries against JSON fixtures
    ├── krule-and-sprule.ps1       # prints a KQL or SPL query on Windows
    └── krule-and-sprule.sh        # prints a KQL or SPL query on Unix shells
```

## Roadmap

- Build an ATT&CK Navigator coverage layer
- Run generated SPL against sanitized fixtures in local Docker Splunk
- Add more Stratus Red Team techniques
- Add technique write-ups after each detection is complete
- Run Prowler after the Terraform target surface exists
