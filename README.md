# AWS Cloud Detection Lab

A detection engineering lab for AWS.

Stratus Red Team detonates attack techniques in a dedicated lab account, CloudTrail collects the telemetry they produce, and each technique gets a Sigma rule tuned against the account's own benign activity.

## Status

Work in progress.

Five detections cover initial access, execution, persistence, privilege escalation,
and defense evasion.

All five convert to Splunk SPL. Three convert to Sentinel KQL. The other two are
marked broken in their `rule.yml`, because Sentinel stores nested CloudTrail
objects as single string columns and neither rule can reach inside one without a
comparison Sigma has no syntax for.


## Roadmap

- A decision on how the two Sentinel-blocked rules express their nested field comparisons
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
5. Convert the rule with `sigma-cli` against a core pipeline per backend. The pipeline supplies what Sigma cannot: the Sentinel table name and column names, and the Splunk index and sourcetype. Where a rule needs a comparison Sigma has no syntax for, the output is refined by hand.
6. Record benign account activity in reference and suppress lists, so every detection is tuned against a known baseline.

## Detections

| Detection | Emulated technique | Tactic |
|---|---|---|
| AWS IAM User Console Login Without MFA | `aws.initial-access.console-login-without-mfa` | Initial Access |
| AWS Execute Commands on SageMaker Notebook Instance Through Lifecycle Configuration | `aws.execution.sagemaker-update-lifecycle-config` | Execution |
| AWS IAM Access Key Created for Another Principal | `aws.persistence.iam-backdoor-user` | Persistence |
| AWS IAM Update User Login Profile | `aws.privilege-escalation.iam-update-user-login-profile` | Privilege Escalation |
| AWS CloudTrail S3 Bucket Logging Lifecycle Change | `aws.defense-evasion.cloudtrail-lifecycle-rule` | Defense Evasion |


## Repository Layout

```
.
├── terraform/                     # lab infrastructure: CloudTrail trail, IAM, and the
│                                  #   SQS queue and OIDC role the Sentinel connector needs
├── core_pipelines/
│   ├── kql_pipe.yml               # Sentinel table name and column mappings
│   └── spl_pipe.yml               # Splunk index and sourcetype
├── detections/                    # one folder per emulated technique
│   └── <technique>/
│       ├── rule.yml               # portable Sigma source, hand authored
│       ├── pipeline.yml           # values specific to one rule, where it needs them
│       └── test/                  # detonation artifacts the rule runs against
├── baseline/                      # benign reference list, suppress list, overlap notes
├── attack-coverage/               # ATT&CK Navigator layer (empty)
├── docs/                          # write-ups (empty)
├── reports/                       # detonation reports (empty)
└── scripts/                       # automation (empty)
```

No detection has all of these yet.

