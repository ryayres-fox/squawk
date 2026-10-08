# cloud-edge.

data "archive_file" "fn" {
  type        = "zip"
  output_path = "${path.module}/.build/fn.zip"
  source {
    filename = "index.py"
    content  = "def handler(event, context):\n    return {'statusCode': 200, 'body': 'squawk lab'}\n"
  }
}

# The function's own role carries no policies: it cannot even write logs. It
# exists only so the function exists.
resource "aws_iam_role" "fn" {
  name = "${local.name}-fn"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_lambda_function" "fn" {
  function_name    = "${local.name}-fn"
  role             = aws_iam_role.fn.arn
  runtime          = "python3.12"
  architectures    = ["arm64"]
  handler          = "index.handler"
  filename         = data.archive_file.fn.output_path
  source_code_hash = data.archive_file.fn.output_base64sha256
  memory_size      = 128
  timeout          = 3
}

# edge:lambda-url-without-auth -- the URL is configured with authorization
# NONE, which is the setting the rule reads. No resource policy grants the
# public `lambda:InvokeFunctionUrl`, so in practice nobody can call it: the
# lab plants the configuration the rule exists for without opening the door.
resource "aws_lambda_function_url" "fn" {
  function_name      = aws_lambda_function.fn.function_name
  authorization_type = "NONE"
}
