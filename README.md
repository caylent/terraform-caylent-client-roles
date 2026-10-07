# Caylent Airlock IAM Roles

Terraform module that creates the Caylent IAM roles, managed policies, and SAML provider in one AWS account.

## Requirements

- Terraform >= 1.3, AWS provider >= 6.0.

## Inputs

| Name                                   | Default    | Description                                                          |
| -------------------------------------- | ---------- | -------------------------------------------------------------------- |
| `roles_scope`                          | `AllRoles` | `AllRoles`, `ReadOnly`, or `ReadWriteWithoutAdmin`                   |
| `additional_restrictions`              | `false`    | Add further denies to the readonly and working roles                 |
| `restrict_assume_role_outside_account` | `false`    | Deny `sts:AssumeRole` outside the account (working and kernel roles) |
| `okta_app_partition`                   | `com-main` | Okta app partition that selects the SAML metadata                    |
| `create_legacy_readonly_role`          | `false`    | Also create `trek10-readonly`                                        |
| `tags`                                 | `{}`       | Tags for all taggable resources                                      |

## Outputs

`account_id`, `saml_provider_arn`, `role_arns`.
