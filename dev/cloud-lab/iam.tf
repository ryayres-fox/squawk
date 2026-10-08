# cloud-iam. Nothing here can be assumed or used from outside this account.

# iam:credential-without-mfa -- a console user with no MFA. It has NO
# permissions at all and must reset its password at first sign-in. The
# generated password lands in Terraform state, which is one more reason the
# state stays on the machine that ran this and never in a repository.
resource "aws_iam_user" "nomfa" {
  name          = "${local.name}-nomfa"
  force_destroy = true
}

resource "aws_iam_user_login_profile" "nomfa" {
  user                    = aws_iam_user.nomfa.name
  password_length         = 32
  password_reset_required = true
}

# A role that can grant itself more: it may rewrite its own policies. Trusted
# by this account only -- an escalation path is a finding about who can reach
# it, and the lab does not hand that reach to anyone outside. Squawk lists it
# among the roles that can grant themselves more; no outside-reach rule fires,
# and that silence is also part of the known answer.
resource "aws_iam_role" "escalates" {
  name = "${local.name}-escalates"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${local.account}:root" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "escalates" {
  name = "rewrite-myself"
  role = aws_iam_role.escalates.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PutRolePolicy", "iam:AttachRolePolicy"]
      Resource = aws_iam_role.escalates.arn
    }]
  })
}
