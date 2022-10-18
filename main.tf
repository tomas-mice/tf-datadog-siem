
# main.tf

terraform {
  backend "s3" {
    bucket         = "terraform-state-717871035839"
    key            = "datadog/siem/terraform.tfstate"
    region         = "eu-west-2"
    dynamodb_table = "terraform-locks"
    encrypt        = true
  }
  required_providers {
    datadog = {
      source = "DataDog/datadog"
    }
    aws = {
      source = "hashicorp/aws"
    }
  }
}

provider "aws" {
  assume_role = {
    role_arn     = "arn:aws:iam::717871035839:role/tbol-gh-action-role-tf-datadog-siem"
    session_name = "githubDataDogPipeline"
  }
}

module "log-detection-rules" {
  source = "./tbol-rules/log-detection"
}

module "workload-security-rules" {
  source = "./tbol-rules/workload-security"
}

module "default-detection-rules" {
  source = "./default-rules"
}