variable "roles_scope" {
  type        = string
  default     = "AllRoles"
  description = "AllRoles grants all 3 role tiers to Caylent. ReadOnly or ReadWriteWithoutAdmin limits the tiers granted."

  validation {
    condition     = contains(["AllRoles", "ReadOnly", "ReadWriteWithoutAdmin"], var.roles_scope)
    error_message = "roles_scope must be AllRoles, ReadOnly, or ReadWriteWithoutAdmin."
  }
}

variable "additional_restrictions" {
  type        = bool
  default     = false
  description = "Adds further permission restrictions to the non-privileged (readonly and working) roles."
}

variable "restrict_assume_role_outside_account" {
  type        = bool
  default     = false
  description = "Prevents the roles from assuming roles outside of the account. Useful for the AWS Organizations management account."
}

variable "okta_app_partition" {
  type        = string
  default     = "com-main"
  description = "Okta app partition that selects the SAML metadata."
}

variable "create_legacy_readonly_role" {
  type        = bool
  default     = false
  description = "Also creates the trek10-readonly role with the same policies as the caylent-readonly role."
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Tags applied to all taggable resources."
}
