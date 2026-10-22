terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.46.0"
    }
  }

  # Production: use a remote backend so the scheduled reaper can destroy agents.
  # backend "s3" {
  #   bucket       = "your-terraform-state"
  #   key          = "balkanid-agents/terraform.tfstate"
  #   region       = "us-east-1"
  #   use_lockfile = true
  # }
}

provider "aws" {
  region = var.aws_region
}
