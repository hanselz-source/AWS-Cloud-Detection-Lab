# AWS Cloud Detection Lab

An AWS detection engineering lab that emulates cloud attacks, captures CloudTrail telemetry, and tests Sigma detections against benign and malicious event fixtures.

## Current state

The repository contains five Stratus Red Team detections.

Each detection has:

- A hand-authored Sigma rule.
- True-positive and true-negative CloudTrail fixtures.
- Expected Splunk SPL and Sentinel KQL output.

The CI workflow checks Sigma syntax, converts every rule for both backends, compares the output with the files under `expected/`, and evaluates the queries against the event fixtures.


## Workflow

1. Provision the lab infrastructure with Terraform, including CloudTrail and the IAM principals used for detonation.
2. Detonate a Stratus Red Team technique in the lab account.
3. Read the CloudTrail events in Amazon Athena.
4. Write a Sigma rule for the behavior and tag it with MITRE ATT&CK.
5. Convert the rule with `sigma-cli` using the shared pipeline for the target backend.
6. Add a rule-specific pipeline when conversion needs an environment-specific value.
8. Record benign activity in the baseline files and test the rule against known event fixtures.

The query scripts print converted queries. They do not run them against Splunk or Sentinel

## Detections

| Detection | Stratus technique | Tactic |
|---|---|---|
| AWS IAM User Console Login Without MFA | `aws.initial-access.console-login-without-mfa` | Initial Access |
| AWS Execute Commands on SageMaker Notebook Instance Through Lifecycle Configuration | `aws.execution.sagemaker-update-lifecycle-config` | Execution |
| AWS IAM Access Key Created for Another Principal | `aws.persistence.iam-backdoor-user` | Persistence |
| AWS IAM Update User Login Profile | `aws.privilege-escalation.iam-update-user-login-profile` | Privilege Escalation |
| AWS CloudTrail S3 Bucket Logging Lifecycle Change | `aws.defense-evasion.cloudtrail-lifecycle-rule` | Defense Impairment |


The files under `core_pipelines/` map CloudTrail fields to the target backend.

A detection can add its own `pipeline.yml` when it needs values that differ by rule or environment.


## Repository layout

```text
.
├── .github/
│   └── workflows/
│       └── ci.yml                 # linting, conversion checks, and fixture tests
├── terraform/                     # CloudTrail, IAM, and Sentinel connector resources
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

- Add a write-up for each detection.
- Add an ATT&CK Navigator coverage layer.
- Add more Stratus Red Team techniques.
