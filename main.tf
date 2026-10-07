data "aws_partition" "current" {}
data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

data "aws_secretsmanager_secret_version" "saml_metadata" {
  secret_id  = "arn:aws:secretsmanager:${data.aws_region.current.region}:567716009496:secret:public/aws-account-federation/${var.okta_app_partition}-xlXdtH"
  version_id = "03988257-5c28-4fa0-bd92-cc71a5985da5"
}

locals {
  partition      = data.aws_partition.current.partition
  account_id     = data.aws_caller_identity.current.account_id
  aws_policy_arn = "arn:${local.partition}:iam::aws:policy"

  create_working = contains(["AllRoles", "ReadWriteWithoutAdmin"], var.roles_scope)
  create_admin   = var.roles_scope == "AllRoles"

  policies = {
    deny-assume-root = {
      description = "Deny sts:assume-root on all client roles"
      document    = file("${path.module}/policies/deny-assume-root.json")
      enabled     = true
    }
    deny-sensitive-reads = {
      description = "Deny read-only user several sensitive read-only actions"
      document    = file("${path.module}/policies/deny-sensitive-reads.json")
      enabled     = true
    }
    deny-deletes-a-to-i = {
      description = "Deny delete-related actions across all services with prefixes starting with A-I"
      document    = file("${path.module}/policies/deny-deletes-a-to-i.json")
      enabled     = local.create_working
    }
    deny-deletes-j-to-z = {
      description = "Deny delete-related actions across all services with prefixes starting with J-Z"
      document    = file("${path.module}/policies/deny-deletes-j-to-z.json")
      enabled     = local.create_working
    }
    deny-ri-purchase = {
      description = "Deny ability to purchase RIs"
      document    = file("${path.module}/policies/deny-ri-purchase.json")
      enabled     = local.create_working
    }
    deny-cloudtrail = {
      description = "Deny ability to turn off/delete CloudTrail"
      document    = file("${path.module}/policies/deny-cloudtrail.json")
      enabled     = local.create_working
    }
    deny-route53-deletes = {
      description = "Deny DELETE action within the ChangeResourceRecordSets API call in Route 53."
      document    = file("${path.module}/policies/deny-route53-deletes.json")
      enabled     = true
    }
    additional-readonly = {
      description = "Allow read-only for Cost Explorer and Support"
      document    = file("${path.module}/policies/additional-readonly.json")
      enabled     = true
    }
    additional-denies = {
      description = "Optional further permission restrictions for non-privileged users"
      document    = file("${path.module}/policies/additional-denies.json")
      enabled     = var.additional_restrictions
    }
    deny-org-account-access-role = {
      description = "Disallows assumption of OrganizationAccountAccessRole used by AWS Organizations for org management"
      document = jsonencode({
        Version = "2012-10-17"
        Statement = [{
          Effect   = "Deny"
          Action   = "sts:AssumeRole"
          Resource = "arn:${local.partition}:iam::*:role/OrganizationAccountAccessRole"
        }]
      })
      enabled = true
    }
    deny-cross-account-role-assumption = {
      description = "Disallows assumption of any role outside of the current account"
      document = jsonencode({
        Version = "2012-10-17"
        Statement = [{
          Effect      = "Deny"
          Action      = "sts:AssumeRole"
          NotResource = "arn:${local.partition}:iam::${local.account_id}:role/*"
        }]
      })
      enabled = var.restrict_assume_role_outside_account
    }
  }

  cross_account_policy = var.restrict_assume_role_outside_account ? ["deny-cross-account-role-assumption"] : []
  additional_denies    = var.additional_restrictions ? ["additional-denies"] : []

  readonly_policies = concat(
    ["deny-sensitive-reads", "additional-readonly", "deny-assume-root"],
    local.additional_denies,
  )

  roles = {
    caylent-readonly = {
      enabled     = true
      trust       = "saml"
      aws_managed = ["ReadOnlyAccess"]
      policies    = local.readonly_policies
    }
    trek10-readonly = {
      enabled     = var.create_legacy_readonly_role
      trust       = "legacy"
      aws_managed = ["ReadOnlyAccess"]
      policies    = local.readonly_policies
    }
    caylent-working = {
      enabled     = local.create_working
      trust       = "saml"
      aws_managed = ["PowerUserAccess", "ReadOnlyAccess"]
      policies = concat(
        [
          "deny-deletes-a-to-i",
          "deny-deletes-j-to-z",
          "deny-ri-purchase",
          "deny-cloudtrail",
          "deny-route53-deletes",
          "deny-assume-root",
          "deny-org-account-access-role",
        ],
        local.additional_denies,
        local.cross_account_policy,
      )
    }
    caylent-kernel = {
      enabled     = local.create_admin
      trust       = "saml"
      aws_managed = ["AdministratorAccess"]
      policies = concat(
        ["deny-org-account-access-role", "deny-assume-root"],
        local.cross_account_policy,
      )
    }
  }

  enabled_roles    = { for k, r in local.roles : k => r if r.enabled }
  enabled_policies = { for k, p in local.policies : k => p if p.enabled }

  trust_policies = {
    saml = jsonencode({
      Version = "2012-10-17"
      Statement = [{
        Effect    = "Allow"
        Principal = { Federated = aws_iam_saml_provider.caylent.arn }
        Action    = ["sts:SetSourceIdentity", "sts:AssumeRoleWithSAML"]
        Condition = { StringEquals = { "SAML:aud" = "https://signin.aws.amazon.com/saml" } }
      }]
    })
    legacy = jsonencode({
      Version = "2012-10-17"
      Statement = [{
        Effect    = "Allow"
        Principal = { AWS = "arn:${local.partition}:iam::800094578424:root" }
        Action    = ["sts:AssumeRole", "sts:SetSourceIdentity", "sts:TagSession"]
      }]
    })
  }

  aws_managed_attachments = merge([
    for role, cfg in local.enabled_roles : {
      for name in cfg.aws_managed : "${role}/${name}" => { role = role, name = name }
    }
  ]...)

  policy_attachments = merge([
    for role, cfg in local.enabled_roles : {
      for key in cfg.policies : "${role}/${key}" => { role = role, key = key }
    }
  ]...)
}

resource "aws_iam_saml_provider" "caylent" {
  name                   = "CAYLENT"
  saml_metadata_document = nonsensitive(jsondecode(data.aws_secretsmanager_secret_version.saml_metadata.secret_string)["Metadata"])
  tags                   = var.tags
}

resource "aws_iam_policy" "this" {
  for_each = local.enabled_policies

  name        = "caylent-${each.key}"
  description = each.value.description
  path        = "/"
  policy      = each.value.document
  tags        = var.tags
}

resource "aws_iam_role" "this" {
  for_each = local.enabled_roles

  name                 = each.key
  max_session_duration = 43200
  assume_role_policy   = local.trust_policies[each.value.trust]
  tags                 = var.tags
}

resource "aws_iam_role_policy_attachment" "aws_managed" {
  for_each = local.aws_managed_attachments

  role       = aws_iam_role.this[each.value.role].name
  policy_arn = "${local.aws_policy_arn}/${each.value.name}"
}

resource "aws_iam_role_policy_attachment" "this" {
  for_each = local.policy_attachments

  role       = aws_iam_role.this[each.value.role].name
  policy_arn = aws_iam_policy.this[each.value.key].arn
}
