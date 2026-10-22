output "execution_role_arn" {
  value       = aws_iam_role.execution.arn
  description = "The agent's own identity. Never a developer role."
}

output "permissions_boundary_arn" {
  value = local.boundary_arn
}

output "agentcore_harness_id" {
  value = aws_bedrockagentcore_harness.this.harness_id
}

output "expires_at" {
  value = var.expires_at
}
