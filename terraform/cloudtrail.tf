# The trail and its bucket already exist and are not managed here.
# This file adds only the notification path Sentinel polls.

resource "aws_sqs_queue" "sentinel" {
  name                    = local.queue_name
  sqs_managed_sse_enabled = true

  # Four days of retention, so an outage on the Sentinel side does not lose objects.
  message_retention_seconds = 345600

  # Long enough for the connector to fetch and process an object before redelivery.
  visibility_timeout_seconds = 300
}

data "aws_iam_policy_document" "queue_policy" {
  statement {
    sid    = "AllowBucketNotifications"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }

    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.sentinel.arn]

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [local.bucket_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_sqs_queue_policy" "sentinel" {
  queue_url = aws_sqs_queue.sentinel.id
  policy    = data.aws_iam_policy_document.queue_policy.json
}

# This resource owns the whole notification configuration of the bucket.
# Any notification set outside Terraform is removed on apply.
resource "aws_s3_bucket_notification" "cloudtrail" {
  bucket = var.cloudtrail_bucket_name

  queue {
    queue_arn     = aws_sqs_queue.sentinel.arn
    events        = ["s3:ObjectCreated:*"]
    filter_prefix = var.cloudtrail_prefix
  }

  depends_on = [aws_sqs_queue_policy.sentinel]
}
