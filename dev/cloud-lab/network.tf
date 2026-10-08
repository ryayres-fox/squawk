# cloud-inventory.

data "aws_vpc" "default" {
  default = true
}

# A security group admitting the world on SSH. Attached to nothing unless
# enable_instance is set, so by default it is a finding in waiting: the
# inventory reads it and no instance answers behind it.
resource "aws_security_group" "ssh_world" {
  name        = "${local.name}-ssh-world"
  description = "Squawk lab: SSH from anywhere, deliberately"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Opt-in. cloud:reachable-admin-port needs an instance that is running, has a
# public address, and sits in a subnet that routes to an internet gateway.
# No key pair, no instance profile and IMDSv2 required: SSH answers, and
# nobody holds a key that opens it. About $6 a month while it runs (t4g.micro;
# check whether your account's free allowance covers it).
data "aws_ami" "al2023" {
  count       = var.enable_instance ? 1 : 0
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-arm64"]
  }
}

resource "aws_instance" "exposed" {
  count                       = var.enable_instance ? 1 : 0
  ami                         = data.aws_ami.al2023[0].id
  instance_type               = "t4g.micro"
  vpc_security_group_ids      = [aws_security_group.ssh_world.id]
  associate_public_ip_address = true
  metadata_options {
    http_tokens = "required"
  }
  tags = {
    Name = "${local.name}-exposed"
  }
}
