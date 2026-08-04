# AWS Cloud Detection Lab

A detection engineering lab for AWS.

Stratus Red Team detonates attack techniques in a dedicated lab account, CloudTrail collects the telemetry they produce, and each technique gets a Sigma rule tuned against the account's own benign activity.

## Status

Work in progress.

Five detections cover initial access, execution, persistence, privilege escalation,
and defense evasion.


## Roadmap

- Detonation artifacts kept per detection, so every rule can run against real events
- A write-up per detection: the technique, the CloudTrail evidence it leaves, and tuning notes
- An ATT&CK Navigator coverage layer built from the rule set
- CI that checks every rule against the Sigma schema on push
- More Stratus techniques, starting with the tactics not yet covered

## Workflow

1. Provision the lab infrastructure with Terraform, including the CloudTrail trail
   and the IAM principals used for detonation.
2. Detonate a Stratus Red Team technique in the account.
3. Read the CloudTrail events it generates in Amazon Athena.
4. Write a Sigma rule for the behavior and tag it with MITRE ATT&CK.
5. Convert the rule with `sigma-cli` through a custom pipeline, then refine the output by hand into Athena SQL, Splunk SPL, and Sentinel KQL. Sigma's generic field mappings leave the raw conversions too broad to use as is.
6. Record benign account activity in reference and suppress lists, so every detection is tuned against a known baseline.

## Detections

| Detection | Emulated technique | Tactic |
|---|---|---|
| AWS IAM User Console Login Without MFA | `aws.initial-access.console-login-without-mfa` | Initial Access |
| AWS Execute Commands on SageMaker Notebook Instance Through Lifecycle Configuration | `aws.execution.sagemaker-update-lifecycle-config` | Execution |
| AWS IAM Access Key Created for Another Principal | `aws.persistence.iam-backdoor-user` | Persistence |
| AWS IAM Update User Login Profile | `aws.privilege-escalation.iam-update-user-login-profile` | Privilege Escalation |
| AWS CloudTrail S3 Bucket Logging Lifecycle Change | `aws.defense-evasion.cloudtrail-lifecycle-rule` | Defense Evasion |


## Repository layout

```
.
├── terraform/                     # lab infrastructure, CloudTrail trail and IAM resources
├── detections/                    # one folder per emulated technique
│   └── <technique>/
│       ├── rule.yml               # portable Sigma source, hand authored
│       ├── pipeline.yml           # pySigma transformations, where a rule needs them
│       └── test/                  # detonation artifacts the rule runs against
├── baseline/                      # benign reference list, suppress list, overlap notes
├── attack-coverage/               # ATT&CK Navigator layer (empty)
├── docs/                          # write-ups (empty)
├── pipeline/                      # shared conversion pipelines (empty)
├── reports/                       # detonation reports (empty)
└── scripts/                       # automation (empty)
```

No detection has all of these yet.

