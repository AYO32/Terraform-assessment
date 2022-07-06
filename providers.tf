provider "aws" {
  region = "us-west-1"
}

data "aws_caller_identity" "current" {}

module "centralised-logs" {
  source        = "Ayo32/centralised-logs/aws"
  aws_elasticsearch_domain      = "logs-data"
  aws_account_id                = "${data.aws_caller_identity.current.account_id}"
  s3_bucket_alb_logs_arn        = "arn:aws:s3:::test.alb.logs"
  s3_bucket_alb_logs_id         = "test.alb.logs"
}

module "elasticsearch" {
  source = "Ayo32/elasticsearch/aws"
  namespace               = "eg"
  stage                   = "dev"
  name                    = "es"
  dns_zone_id             = "Z14EN2YD427LRQ"
  security_groups         = ["sg-XXXXXXXXX", "sg-YYYYYYYY"]
  vpc_id                  = ["vpc-XXXXXXXXX"]
  subnet_ids              = ["subnet-XXXXXXXXX", "subnet-YYYYYYYY"]
  zone_awareness_enabled  = "true"
  elasticsearch_version   = "6.5"
  instance_type           = "t2.small.elasticsearch"
  instance_count          = 4
  ebs_volume_size         = 10
  iam_role_arns           = ["arn:aws:iam::XXXXXXXXX:role/ops", "arn:aws:iam::XXXXXXXXX:role/dev"]
  iam_actions             = ["es:ESHttpGet", "es:ESHttpPut", "es:ESHttpPost"]
  encrypt_at_rest_enabled = true
  kibana_subdomain_name   = "kibana-es"

  advanced_options = {
    "rest.action.multi.allow_explicit_index" = "true"
  }
}