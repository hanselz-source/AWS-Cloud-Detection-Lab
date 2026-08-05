output "sentinel_role_arn" {
  description = "Paste into the Role to add field on the Amazon Web Services S3 connector page."
  value       = aws_iam_role.sentinel.arn
}

output "sentinel_sqs_url" {
  description = "Paste into the SQS URL field on the Amazon Web Services S3 connector page."
  value       = aws_sqs_queue.sentinel.url
}
