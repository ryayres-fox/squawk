# cloud-analyzer: AWS's own external-access analyzer, which is free. Within a
# few minutes of the resources above existing it reports the open bucket,
# topic, queue and registry -- analyzer:analyzer-public -- and Squawk shows its
# answer beside its own policy readers'.
resource "aws_accessanalyzer_analyzer" "account" {
  analyzer_name = "${local.name}-analyzer"
  type          = "ACCOUNT"
}

# Opt-in. Security Hub has a free trial and charges after it; with it on, the
# cloudaws service has something to read.
resource "aws_securityhub_account" "hub" {
  count = var.enable_securityhub ? 1 : 0
}
