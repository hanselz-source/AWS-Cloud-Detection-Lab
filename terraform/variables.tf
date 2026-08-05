variable "aws_region" {
  description = "Region for the SQS queue. Use the region the CloudTrail bucket lives in."
  type        = string
}

variable "aws_profile" {
  description = "Local AWS CLI profile used to apply this configuration."
  type        = string
}

variable "cloudtrail_bucket_name" {
  description = "Existing S3 bucket CloudTrail delivers to. Referenced, not created."
  type        = string
}

variable "cloudtrail_prefix" {
  description = "Key prefix Sentinel reads. One queue serves one prefix, so keep this specific enough to exclude CloudTrail-Digest."
  type        = string
}

variable "sentinel_workspace_id" {
  description = "Microsoft Sentinel workspace ID, shown on the connector page. Pins the role to one workspace."
  type        = string
}

variable "name_prefix" {
  description = "Prefix for resource names created here."
  type        = string
  default     = "cloud-detection-lab"
}

variable "create_oidc_provider" {
  description = "Set false if an OIDC provider for sts.windows.net already exists, for example one created by Defender for Cloud. AWS permits one provider per URL."
  type        = bool
  default     = true
}
