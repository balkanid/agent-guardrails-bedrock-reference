locals {
  role_path = "/balkanid-agents/"
  role_name = "agent-${var.agent_name}"
  # AgentCore harness names allow alphanumeric and underscores only.
  harness_name = replace(var.agent_name, "-", "_")

  is_child      = var.parent_agent_name != ""
  boundary_name = "agent-boundary-${local.is_child ? var.parent_agent_name : var.agent_name}"
  boundary_arn  = local.is_child ? data.aws_iam_policy.parent_boundary[0].arn : aws_iam_policy.boundary[0].arn

  common_tags_raw = {
    "balkanid-agent"      = var.agent_name
    "balkanid-owner"      = var.owner_email
    "balkanid-expires-at" = var.expires_at
    "balkanid-parent"     = var.parent_agent_name
    "balkanid-managed"    = "true"
  }
  # IAM rejects empty tag values on some APIs; drop them.
  common_tags = { for k, v in local.common_tags_raw : k => v if v != "" }
}

# --- Permissions boundary: the most any agent in this family can ever do ---------------

data "aws_iam_policy_document" "boundary" {
  statement {
    sid       = "UpperBound"
    effect    = "Allow"
    actions   = [for s in var.allowed_services : "${s}:*"]
    resources = ["*"]
  }

  statement {
    sid    = "NeverIdentityOrOrg"
    effect = "Deny"
    actions = [
      "iam:*",
      "organizations:*",
      "sso:*",
      "sso-admin:*",
      "identitystore:*",
      "sts:AssumeRole",
      "sts:GetSessionToken",
      "sts:GetFederationToken",
      "account:*",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "NeverDestroyData"
    effect = "Deny"
    actions = [
      "s3:DeleteBucket",
      "s3:PutBucketPolicy",
      "s3:PutBucketAcl",
      "dynamodb:DeleteTable",
      "kms:ScheduleKeyDeletion",
      "kms:DisableKey",
      "logs:DeleteLogGroup",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "boundary" {
  count       = local.is_child ? 0 : 1
  name        = local.boundary_name
  path        = local.role_path
  description = "Permissions boundary for agent ${var.agent_name} and its subagents (BalkanID reference)."
  policy      = data.aws_iam_policy_document.boundary.json
  tags        = local.common_tags
}

data "aws_iam_policy" "parent_boundary" {
  count = local.is_child ? 1 : 0
  name  = local.boundary_name
}

# --- The agent's own execution role (never the developer's) ----------------------------

data "aws_iam_policy_document" "trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["bedrock-agentcore.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.aws_account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:bedrock-agentcore:${var.aws_region}:${var.aws_account_id}:*"]
    }
  }
}

resource "aws_iam_role" "execution" {
  name                 = local.role_name
  path                 = local.role_path
  description          = "Own identity for agent ${var.agent_name}; approved in BalkanID; expires ${var.expires_at}."
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  permissions_boundary = local.boundary_arn
  tags                 = local.common_tags
}

resource "aws_iam_role_policy" "invoke" {
  name = "invoke-foundation-model"
  role = aws_iam_role.execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream",
          "bedrock:Converse",
          "bedrock:ConverseStream",
        ]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "approved" {
  for_each   = toset(var.agent_policy_arns)
  role       = aws_iam_role.execution.name
  policy_arn = each.value
}

# --- The agent ------------------------------------------------------------------------

resource "aws_bedrockagentcore_harness" "this" {
  harness_name       = local.harness_name
  execution_role_arn = aws_iam_role.execution.arn

  model {
    bedrock_model_config {
      model_id = var.foundation_model
    }
  }

  system_prompt {
    text = var.agent_instruction
  }

  depends_on = [aws_iam_role_policy.invoke, aws_iam_role_policy_attachment.approved]
}
