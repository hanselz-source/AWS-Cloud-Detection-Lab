# AWS Cloud Detection Lab

A detection engineering lab for AWS. Attack techniques are emulated with [Stratus Red Team](https://stratus-red-team.cloud/) in a dedicated lab account, the CloudTrail telemetry they produce is collected, and each technique gets a Sigma rule that is converted, refined, and tuned against the account's own benign activity.

## Status

Work in progress. Five detections are written, covering initial access, execution, persistence, privilege escalation, and defense evasion. Refinement queries are complete for the IAM backdoor user and login profile detections.

## Roadmap

- Refinement queries in Athena SQL, Splunk SPL, and Sentinel KQL for the remaining three detections
- Captured detonation artifacts stored per detection so each rule can be validated against real events
- A write-up per detection covering the technique, the CloudTrail evidence it leaves, and tuning notes
- An ATT&CK Navigator coverage layer built from the rule set
- CI linting so every rule is checked against the Sigma schema on push
- Additional Stratus techniques, prioritizing tactics not yet covered

## Workflow

1. Terraform provisions the lab infrastructure, including CloudTrail and the IAM principals used for detonation.
2. A Stratus Red Team technique is detonated in the account.
3. The CloudTrail events it generates are examined with Amazon Athena.
4. A Sigma rule is written for the behavior and tagged with MITRE ATT&CK.
5. sigma-cli converts the rule through a custom processing pipeline, and the generated queries are refined by hand into Athena SQL, Splunk SPL, and Microsoft Sentinel KQL. Sigma's generic field mappings leave the raw conversions too broad to use as is.
6. Benign account activity is recorded in reference and suppress lists so every detection is tuned against a known baseline.

## Detections

| Detection | Emulated technique | Tactic |
|---|---|---|
| AWS IAM User Console Login Without MFA | aws.initial-access.console-login-without-mfa | Initial Access |
| AWS Execute Commands on SageMaker Notebook Instance Through Lifecycle Configuration | aws.execution.sagemaker-update-lifecycle-config | Execution |
| AWS IAM Access Key Created for Another Principal | aws.persistence.iam-backdoor-user | Persistence |
| AWS IAM Update User Login Profile | aws.privilege-escalation.iam-update-user-login-profile | Privilege Escalation |
| AWS CloudTrail S3 Bucket Logging Lifecycle Change | aws.defense-evasion.cloudtrail-lifecycle-rule | Defense Evasion |

Each folder under `detections/` holds the Sigma rule, a conversion pipeline where one is needed, and refinement queries for Athena, Splunk, and Sentinel as they are completed.

## Repository layout

- `terraform/`: lab infrastructure, including the CloudTrail trail and IAM resources
- `detections/`: one folder per emulated technique
- `baseline/`: benign reference list, suppress list, and overlap notes built from the account's real activity
- `attack-coverage/`, `docs/`, `pipeline/`, `reports/`, `scripts/`: reserved for the ATT&CK Navigator layer, write-ups, shared pipelines, detonation reports, and automation as the lab grows
