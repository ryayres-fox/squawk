# cloud-storage. Both buckets are EMPTY. Public here means public READ of
# nothing, which is the weakness the rule names without anything to leak.

# storage:bucket-public -- a bucket policy granting anyone GetObject, with the
# bucket's own block turned off so the policy stands.
resource "aws_s3_bucket" "open" {
  bucket        = "${local.name}-open"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "open" {
  bucket                  = aws_s3_bucket.open.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "open" {
  bucket = aws_s3_bucket.open.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "SquawkLabPublicRead"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.open.arn}/*"
    }]
  })
  depends_on = [aws_s3_bucket_public_access_block.open]
}

# The website endpoint is what the CloudFront distribution in frontdoor.tf
# fetches from, and it is plain HTTP by construction -- which is the point.
resource "aws_s3_bucket_website_configuration" "open" {
  bucket = aws_s3_bucket.open.id
  index_document {
    suffix = "index.html"
  }
}

# storage:bucket-public-policy-blocked -- the same public policy, held shut by
# the bucket's own RestrictPublicBuckets. A reader that reads only the policy
# calls this public; it is not, and Squawk must say "medium, held shut".
resource "aws_s3_bucket" "held" {
  bucket        = "${local.name}-held"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "held" {
  bucket                  = aws_s3_bucket.held.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = false
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "held" {
  bucket = aws_s3_bucket.held.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "SquawkLabHeldShut"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.held.arn}/*"
    }]
  })
  depends_on = [aws_s3_bucket_public_access_block.held]
}
