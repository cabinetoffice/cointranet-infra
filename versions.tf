terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.55"
    }
    postgresql = {
      source  = "cyrilgdn/postgresql"
      version = "1.21.0"
    }
  }
}
