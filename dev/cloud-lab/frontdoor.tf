# cloud-frontdoor.

# frontdoor:api-open-to-the-internet -- a REST API whose one method needs no
# authorization. The integration is MOCK: there is no backend, the answer is
# a fixed 200, and the stage is throttled to one request a second.
resource "aws_api_gateway_rest_api" "api" {
  name = "${local.name}-api"
}

resource "aws_api_gateway_method" "get" {
  rest_api_id   = aws_api_gateway_rest_api.api.id
  resource_id   = aws_api_gateway_rest_api.api.root_resource_id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "get" {
  rest_api_id       = aws_api_gateway_rest_api.api.id
  resource_id       = aws_api_gateway_rest_api.api.root_resource_id
  http_method       = aws_api_gateway_method.get.http_method
  type              = "MOCK"
  request_templates = { "application/json" = "{\"statusCode\": 200}" }
}

resource "aws_api_gateway_method_response" "ok" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  resource_id = aws_api_gateway_rest_api.api.root_resource_id
  http_method = aws_api_gateway_method.get.http_method
  status_code = "200"
}

resource "aws_api_gateway_integration_response" "ok" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  resource_id = aws_api_gateway_rest_api.api.root_resource_id
  http_method = aws_api_gateway_method.get.http_method
  status_code = aws_api_gateway_method_response.ok.status_code
  depends_on  = [aws_api_gateway_integration.get]
}

resource "aws_api_gateway_deployment" "api" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  depends_on  = [aws_api_gateway_integration_response.ok]
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_api_gateway_stage" "lab" {
  rest_api_id   = aws_api_gateway_rest_api.api.id
  deployment_id = aws_api_gateway_deployment.api.id
  stage_name    = "lab"
}

resource "aws_api_gateway_method_settings" "throttle" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  stage_name  = aws_api_gateway_stage.lab.stage_name
  method_path = "*/*"
  settings {
    throttling_rate_limit  = 1
    throttling_burst_limit = 1
  }
}

# frontdoor:cloudfront-without-waf and frontdoor:cloudfront-plaintext-origin --
# a distribution with no web ACL, fetching from the open bucket's website
# endpoint over plain HTTP. The bucket is empty, so it serves 404s.
data "aws_cloudfront_cache_policy" "optimized" {
  name = "Managed-CachingOptimized"
}

resource "aws_cloudfront_distribution" "cdn" {
  enabled     = true
  comment     = "${local.name} — deliberately without WAF, plain-HTTP origin"
  price_class = "PriceClass_100"

  origin {
    origin_id   = "open-bucket-website"
    domain_name = aws_s3_bucket_website_configuration.open.website_endpoint
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "http-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    target_origin_id       = "open-bucket-website"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    cache_policy_id        = data.aws_cloudfront_cache_policy.optimized.id
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}
