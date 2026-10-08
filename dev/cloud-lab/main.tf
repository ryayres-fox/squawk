resource "random_id" "suffix" {
  byte_length = 3
}

locals {
  name    = "${var.lab_name}-${random_id.suffix.hex}"
  account = var.account_id
}

data "aws_caller_identity" "me" {}

# ---------------------------------------------------------------------------
# The identity Squawk reads AS. Read-only, because Squawk refuses to treat a
# write-capable identity as a clean read, and separate from the profile that
# deployed the lab for the same reason. Trusted by this account only.
# ---------------------------------------------------------------------------

resource "aws_iam_role" "auditor" {
  name = "${local.name}-auditor"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${local.account}:root" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "auditor" {
  for_each   = toset(["SecurityAudit", "ViewOnlyAccess"])
  role       = aws_iam_role.auditor.name
  policy_arn = "arn:aws:iam::aws:policy/${each.value}"
}
