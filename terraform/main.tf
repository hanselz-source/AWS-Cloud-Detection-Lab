data "aws_caller_identity" "current" {}

locals {
  # Microsoft Entra ID, commercial cloud. Government cloud uses different values.
  oidc_url        = "sts.windows.net/33e01921-4d64-4f8c-a055-5bdaffd5e33d/"
  oidc_thumbprint = "626d44e704d1ceabe3bf0d53397464ac8080142c"
  oidc_audience   = "api://1462b192-27f7-4cb9-8523-0f4ecb54b47e"

  # Both prefixes are load bearing. The connector matches on them and fails silently without.
  role_name    = "OIDC_${var.name_prefix}-sentinel"
  session_name = "MicrosoftSentinel_${var.sentinel_workspace_id}"

  queue_name = "${var.name_prefix}-sentinel-cloudtrail"
  bucket_arn = "arn:aws:s3:::${var.cloudtrail_bucket_name}"

  oidc_provider_arn = var.create_oidc_provider ? aws_iam_openid_connect_provider.sentinel[0].arn : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/${local.oidc_url}"
}
