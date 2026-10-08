# The cloud lab: a small, deliberately weak AWS estate with known answers, the
# cloud counterpart of `../lab-targets.py`. See README.md before applying.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws     = { source = "hashicorp/aws", version = "~> 6.0" }
    random  = { source = "hashicorp/random", version = "~> 3.6" }
    archive = { source = "hashicorp/archive", version = "~> 2.4" }
  }
}

provider "aws" {
  region  = var.region
  profile = var.deploy_profile

  # The rail this whole directory rests on. Terraform refuses to plan or apply
  # against any account but the one named here, so a profile that resolves
  # somewhere else -- a work SSO session left in ~/.aws/config, a default
  # profile pointing at the wrong place -- stops the run before anything is
  # created. Every resource below is weak on purpose; the only thing that
  # makes that safe is that it lands in an account built to hold it.
  allowed_account_ids = [var.account_id]

  default_tags {
    tags = {
      project = "squawk-lab"
      purpose = "deliberately-weak-test-resources"
    }
  }
}
