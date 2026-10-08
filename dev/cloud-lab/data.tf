# cloud-dataservices. Every grant to `*` below is a READ of metadata or of an
# empty registry. The rule fires on the principal, not on the action, so a
# read is enough to plant it and nothing an outsider can do costs anything.

# data:messaging-open-to-any-principal (topic)
resource "aws_sns_topic" "open" {
  name = "${local.name}-topic"
}

resource "aws_sns_topic_policy" "open" {
  arn = aws_sns_topic.open.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "SquawkLabAnyoneMayRead"
      Effect    = "Allow"
      Principal = "*"
      Action    = "SNS:GetTopicAttributes"
      Resource  = aws_sns_topic.open.arn
    }]
  })
}

# data:messaging-open-to-any-principal (queue)
resource "aws_sqs_queue" "open" {
  name = "${local.name}-queue"
}

resource "aws_sqs_queue_policy" "open" {
  queue_url = aws_sqs_queue.open.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "SquawkLabAnyoneMayRead"
      Effect    = "Allow"
      Principal = "*"
      Action    = "sqs:GetQueueAttributes"
      Resource  = aws_sqs_queue.open.arn
    }]
  })
}

# data:registry-open-to-any-principal -- anyone may pull from an EMPTY
# repository.
resource "aws_ecr_repository" "open" {
  name         = "${local.name}-registry"
  force_delete = true
}

resource "aws_ecr_repository_policy" "open" {
  repository = aws_ecr_repository.open.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "SquawkLabAnyoneMayPull"
      Effect    = "Allow"
      Principal = "*"
      Action    = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]
    }]
  })
}

# A secret, so the read of Secrets Manager has something to count. It holds a
# fixed placeholder, not a credential, and is deleted with no recovery window
# when the lab is destroyed. About $0.40 a month while it exists.
resource "aws_secretsmanager_secret" "placeholder" {
  name                    = "${local.name}-placeholder"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "placeholder" {
  secret_id     = aws_secretsmanager_secret.placeholder.id
  secret_string = "squawk-lab-placeholder-not-a-credential"
}

# cloud-containers: an empty ECS cluster. A cluster with no service costs
# nothing; a public Fargate service would, and EKS costs about $70 a month for
# the control plane alone, so neither is planted. Those rules stay unexercised
# on this lab, and the validator says so rather than calling them clean.
resource "aws_ecs_cluster" "lab" {
  name = "${local.name}-cluster"
}
