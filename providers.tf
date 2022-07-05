provider "aws" {
  region = "us-west-1"
}

data "aws_caller_identity" "current" {}

module "centralised-logs" {
  source        = "Ayo32/centralised-logs/aws"
  version       = "0.1.0"
  aws_elasticsearch_domain      = "logs-data"
  vpc_id                        = "vpc-9999999999"
  subnet_ids                    = ["subnet-999999999999"]
  ingress_allow_cidr_blocks     = ["172.10.0.0/16"]
  ingress_allow_security_groups = ["sg-9999999999"] # vpc-99999999 default
  aws_account_id                = "${data.aws_caller_identity.current.account_id}"
  s3_bucket_alb_logs_arn        = "arn:aws:s3:::test.alb.logs"
  s3_bucket_alb_logs_id         = "test.alb.logs"
}