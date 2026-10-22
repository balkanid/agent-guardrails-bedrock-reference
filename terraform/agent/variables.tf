variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "aws_account_id" {
  type        = string
  description = "12-digit AWS account id."
}

variable "agent_name" {
  type        = string
  description = "Agent name approved in BalkanID. Also the Terraform workspace name."

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{2,40}$", var.agent_name))
    error_message = "agent_name must be 3-41 lowercase letters, digits and hyphens."
  }
}

variable "owner_email" {
  type        = string
  description = "Human owner on the BalkanID approval. Stored as a tag for attribution."
}

variable "expires_at" {
  type        = string
  description = "Approved expiry (UTC, YYYY-MM-DDTHH:MM:SSZ). The reaper destroys the agent after this time."

  validation {
    condition     = can(regex("^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$", var.expires_at))
    error_message = "expires_at must look like 2026-10-22T18:00:00Z."
  }
}

variable "parent_agent_name" {
  type        = string
  default     = ""
  description = "For a subagent: its parent. The child uses the parent's permissions boundary and can never exceed it."
}

variable "agent_policy_arns" {
  type        = list(string)
  default     = []
  description = "Extra policies approved for this agent on the CREATE_SERVICE_ACCOUNT request. Model invocation and logging are always included."
}

variable "allowed_services" {
  type        = list(string)
  default     = ["bedrock", "bedrock-agentcore", "logs", "s3", "dynamodb", "lambda", "secretsmanager", "kms", "ssm", "cloudwatch", "xray", "ec2", "ecs", "rds"]
  description = "Upper bound of AWS services the agent (and its subagents) can ever use."
}

variable "foundation_model" {
  type    = string
  default = "amazon.nova-micro-v1:0"
}

variable "agent_instruction" {
  type    = string
  default = "You are a developer assistant. You act only through your own identity and never on production systems without an approved grant."
}
