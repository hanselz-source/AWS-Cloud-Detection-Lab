resource "aws_iam_openid_connect_provider" "sentinel" {
  count = var.create_oidc_provider ? 1 : 0

  url             = "https://${local.oidc_url}"
  client_id_list  = [local.oidc_audience]
  thumbprint_list = [local.oidc_thumbprint]
}

data "aws_iam_policy_document" "sentinel_trust" {
  statement {
    sid     = "SentinelWebIdentity"
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [local.oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_url}:aud"
      values   = [local.oidc_audience]
    }

    # Scopes the role to one workspace. Without it any Sentinel tenant could assume it.
    condition {
      test     = "StringEquals"
      variable = "sts:RoleSessionName"
      values   = [local.session_name]
    }
  }
}

resource "aws_iam_role" "sentinel" {
  name               = local.role_name
  description        = "Read only access for the Microsoft Sentinel AWS S3 connector."
  assume_role_policy = data.aws_iam_policy_document.sentinel_trust.json
}

# Microsoft documents four managed policies here. These inline statements grant the
# same operations scoped to one bucket prefix and one queue instead of account wide.
data "aws_iam_policy_document" "sentinel_read" {
  statement {
    sid       = "ReadCloudTrailObjects"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${local.bucket_arn}/${var.cloudtrail_prefix}*"]
  }

  statement {
    sid       = "ListCloudTrailPrefix"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [local.bucket_arn]

    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["${var.cloudtrail_prefix}*"]
    }
  }

  # DeleteMessage is required. The connector drains the queue as it reads,
  # so read only SQS access leaves messages redelivering forever.
  statement {
    sid    = "DrainNotificationQueue"
    effect = "Allow"

    actions = [
      "sqs:ReceiveMessage",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
      "sqs:ChangeMessageVisibility",
    ]

    resources = [aws_sqs_queue.sentinel.arn]
  }
}

resource "aws_iam_role_policy" "sentinel_read" {
  name   = "sentinel-cloudtrail-read"
  role   = aws_iam_role.sentinel.id
  policy = data.aws_iam_policy_document.sentinel_read.json
}
