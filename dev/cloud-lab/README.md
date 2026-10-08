# The cloud lab

A small AWS estate that is weak on purpose, with the answer written beside each
weakness. It is the cloud counterpart of [`../lab-targets.py`](../lab-targets.py):
a cloud service with no account it is known to find something in is a service
nobody can say ran right.

`terraform apply` plants it in a **dedicated test account**. Then

    ./dev/lab-targets.py check --only cloud \
        --aws-profile squawk-lab-auditor --aws-account <id> --aws-lab <lab_name> \
        --report VALIDATION.md

runs both cloud services against it and holds each of their stages to what was
planted. A stage that read the lab and named every weakness is `validated`. A
stage the account could not exercise — a service the account's plan does not
offer, a read that was refused — is a SKIP that says why, and it is `not
exercised` in the report. A release claims only what the report says was
validated.

## Two rails, both enforced rather than requested

**The account.** Terraform's provider is pinned with `allowed_account_ids`, so
it refuses to plan or apply against any account but the one you name. The
validator asks AWS which account the profile resolves to before it runs
anything, and stops if it is not the one you named. A profile left over from
other work — an SSO session, a default profile — cannot be read by mistake.

**Nothing planted lets an outsider in.** Every grant to `*` is a read of
metadata or of something empty: an empty bucket, an empty registry, a topic's
attributes, a queue's attributes. The Lambda function URL is configured with
authorization `NONE` — which is what the rule reads — and no resource policy
lets the public invoke it. The console user has no permissions and must reset
its password. The role that can rewrite its own policy is trusted by this
account alone. The lab plants the configurations Squawk exists to name without
opening any of them.

## The account

Use one that holds nothing else.

1. A new AWS account on the **Free plan**, with a personal email address.
   A Free-plan account cannot be charged unless you upgrade it.
2. MFA on the root user, then never use root again.
3. An IAM Identity Center user or IAM user with `AdministratorAccess` for
   deploying the lab. This is the `deploy_profile`.
4. Write its account id down. That is `account_id`, here and in the check.

## Deploy

    cd dev/cloud-lab
    terraform init
    terraform apply -var account_id=<id> -var deploy_profile=<profile>

`apply` prints:

- `lab_name` — the prefix every resource carries; the check's `--aws-lab`.
- `aws_config_snippet` — a profile for the read-only auditor role. Add it to
  `~/.aws/config`. Squawk reads as that role, never as the deploying identity:
  it treats a write-capable identity as a gap, and the deploy identity is one.
- `validate_command` — the check, filled in.

Access Analyzer takes a few minutes to report the open resources after they
exist. Run the check after that, not straight after `apply`.

## What is planted, and what Squawk must say

| Stage | Planted | Expected |
|---|---|---|
| storage | a bucket with a public read policy; a second with the same policy held shut by its own block | `storage:bucket-public`, `storage:bucket-public-policy-blocked` |
| identity | a console user with no MFA; a role that can rewrite its own policy, trusted by the account only | `iam:credential-without-mfa`; nothing reachable from outside |
| edge | a Lambda function URL with authorization `NONE` | `edge:lambda-url-without-auth` |
| frontdoor | a REST API with an unauthenticated method; a CloudFront distribution with no WAF and a plain-HTTP origin | `frontdoor:api-open-to-the-internet`, `frontdoor:cloudfront-without-waf`, `frontdoor:cloudfront-plaintext-origin` |
| data services | a topic, a queue and a registry readable by `*`; a placeholder secret | `data:messaging-open-to-any-principal`, `data:registry-open-to-any-principal` |
| external access | AWS's own account analyzer | `analyzer:analyzer-public` |
| inventory | a security group open to the world on SSH | read, by name |
| containers | an empty ECS cluster | read, by name |
| watching, estate | nothing; they read what the account has turned on and how it is organised | the stage runs |

These are predictions from reading the code, and the first run against the
test account is what settles them. A miss there is the check doing its job: either
the lab did not plant what it says, or the stage does not see what it should.

## Cost

Everything not behind a flag is free or near it. The placeholder secret is
about $0.40 a month. The REST API is throttled to one request a second and
CloudFront serves an empty bucket.

| Flag | What it adds | Why it is off |
|---|---|---|
| `enable_instance` | a `t4g.micro` behind the SSH group, so `cloud:reachable-admin-port` has something to find | about $6 a month while it runs, and an address on the internet |
| `enable_securityhub` | Security Hub, so the `cloudaws` service has findings to read | charges after its trial |

Not planted at all: a public ECS service, an EKS cluster (about $70 a month for
the control plane), an RDS instance and a load balancer. Their rules stay
unexercised on this lab, and the report says so instead of calling them clean.

## Tear down

    terraform destroy -var account_id=<id> -var deploy_profile=<profile>

The state file holds the console user's generated password and every ARN in
the lab. It stays on the machine that ran `apply` — `.gitignore` keeps it out of
the repository, and the repository's own hygiene check refuses a `.tfstate`.
