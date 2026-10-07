output "account_id" {
  description = "AWS account ID."
  value       = local.account_id
}

output "saml_provider_arn" {
  description = "ARN of the CAYLENT SAML provider."
  value       = aws_iam_saml_provider.caylent.arn
}

output "role_arns" {
  description = "Map of role name to role ARN."
  value       = { for k, r in aws_iam_role.this : k => r.arn }
}
