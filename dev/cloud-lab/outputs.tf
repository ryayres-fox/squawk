output "lab_name" {
  description = "The prefix the validator looks for in every stage's evidence."
  value       = local.name
}

output "auditor_role_arn" {
  description = "The read-only role Squawk runs as."
  value       = aws_iam_role.auditor.arn
}

output "aws_config_snippet" {
  description = "Paste into ~/.aws/config. Squawk reads as this profile; Terraform deploys as the other."
  value       = <<-EOT
    [profile squawk-lab-auditor]
    role_arn       = ${aws_iam_role.auditor.arn}
    source_profile = ${var.deploy_profile}
    region         = ${var.region}
  EOT
}

output "validate_command" {
  description = "Run from the Squawk checkout once the lab exists."
  value       = "./dev/lab-targets.py check --only cloud --aws-profile squawk-lab-auditor --aws-account ${var.account_id} --aws-lab ${local.name}"
}
