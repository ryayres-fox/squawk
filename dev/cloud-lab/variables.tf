variable "account_id" {
  description = "The dedicated test account. Terraform refuses every other account."
  type        = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id is twelve digits."
  }
}

variable "deploy_profile" {
  description = "The AWS CLI profile that deploys the lab. No default: name it every time."
  type        = string
}

variable "region" {
  description = "Where the regional resources go."
  type        = string
  default     = "us-east-1"
}

variable "lab_name" {
  description = "Prefix for every resource name. The validator looks for it in each stage's evidence."
  type        = string
  default     = "squawk-lab"
}

# Opt-in, because each one costs money while it exists or exposes something
# beyond a read. Everything not behind a flag is free or near it; see README.

variable "enable_instance" {
  description = "A micro instance behind the world-open SSH group, so reachable-admin-port has something to find."
  type        = bool
  default     = false
}

variable "enable_securityhub" {
  description = "Turn on Security Hub, so the cloudaws service has an answer to read. Charges after its trial."
  type        = bool
  default     = false
}
