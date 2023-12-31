#
# Miscellaneous resources and settings
#

terraform {
  backend "s3" {
    bucket = "cointranet-wagtail"
    key    = "terraform/cointranet"
    region = "eu-west-2"
  }
}

provider "postgresql" {
  host      = null_resource.postgres.triggers.host
  port      = null_resource.postgres.triggers.port
  username  = null_resource.postgres.triggers.username
  password  = null_resource.postgres.triggers.password
  superuser = false
  database  = "wagtail"
  sslmode   = "require"
}

provider "aws" {
  region = local.region
}

# This null resource and  are required due to https://github.com/hashicorp/terraform-provider-postgresql/issues/2
resource "null_resource" "postgres" {
  triggers = {
    host     = module.db.db_instance_address
    port     = module.db.db_instance_port
    endpoint = module.db.db_instance_endpoint
    username = module.db.db_instance_username
    password = jsondecode(data.aws_secretsmanager_secret_version.postgres_password.secret_string)["password"]
  }
}

resource "random_password" "django_secret_key" {
  length  = 128
  special = false
}

resource "random_password" "application_password" {
  length  = 64
  special = false
}

resource "random_password" "admin_password" { # TODO: turn this into a user configurable secret and read it from AWS directly
  length  = 64
  special = false
}

data "aws_availability_zones" "available" {}
data "aws_caller_identity" "current" {}
data "aws_secretsmanager_secret_version" "postgres_password" {
  secret_id = module.db.db_instance_master_user_secret_arn
}

data "aws_ip_ranges" "s3_ranges" {
  regions  = ["eu-west-2"]
  services = ["s3"]
}

locals {
  admin_email = "co-intranet-project@cabinetoffice.gov.uk" # param

  region     = "eu-west-2"
  name       = basename(path.cwd)
  account_id = data.aws_caller_identity.current.account_id
  workspace = terraform.workspace
  dns = "intranet.codatt.net"

  vpc_cidr = "10.0.0.0/16" # param
  azs      = slice(data.aws_availability_zones.available.names, 0, 3)

  container_name = "wagtail"
  container_port = 8080

  codestar = "arn:aws:codestar-connections:eu-west-2:527922690890:connection/d277085d-2da1-4954-9143-93f7db172ea0" # param
  acm_certificate_arn = "arn:aws:acm:eu-west-2:503646200365:certificate/9fd40d1d-d3a7-41e0-925b-734da58e2e37"

  allowed_ip_ranges = ["51.149.8.0/25","51.149.9.112/29","51.149.9.240/29"] # param

  tags = {
    Name = local.name
    Workspace = terraform.workspace
  }
}

################################################################################
# Cluster
################################################################################

module "ecs_cluster" {
  source = "terraform-aws-modules/ecs/aws" # TODO: tag at version

  cluster_name = local.name

  default_capacity_provider_use_fargate = false

  #  fargate_capacity_providers = {
  #    FARGATE = {
  #      default_capacity_provider_strategy = {
  #        weight = 50
  #      }
  #    }
  #  }
  cluster_configuration = {
    execute_command_configuration = {
      logging = "OVERRIDE"
      log_configuration = {
        cloud_watch_log_group_name = "/aws/ecs/${local.name}"
      }
    }
  }

  autoscaling_capacity_providers = {
    intranet = {
      auto_scaling_group_arn         = module.autoscaling["intranet"].autoscaling_group_arn
      managed_termination_protection = "ENABLED"

      managed_scaling = {
        maximum_scaling_step_size = 2
        minimum_scaling_step_size = 1
        status                    = "ENABLED"
        target_capacity           = 2
      }

    }
  }

  tags = local.tags
}

################################################################################
# Service
################################################################################

module "ecs_service" {
  source = "terraform-aws-modules/ecs/aws//modules/service"

  # Service
  name        = local.name
  cluster_arn = module.ecs_cluster.cluster_arn

  cpu    = 2048
  memory = 4096

  # Task Definition
  requires_compatibilities = ["EC2"]
  capacity_provider_strategy = {
    # On-demand instances
    intranet = {
      capacity_provider = module.ecs_cluster.autoscaling_capacity_providers["intranet"].name
      weight            = 1
      base              = 1
    }
  }
  create_task_exec_iam_role = true
  create_task_exec_policy   = true
  task_exec_iam_role_policies = {
    AmazonEC2ContainerServiceforEC2Role = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role",
    AmazonSSMManagedInstanceCore        = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
  }


  # Container definition(s)
  container_definitions = {
    (local.container_name) = {
      image = "${local.account_id}.dkr.ecr.${local.region}.amazonaws.com/${local.name}:latest"
      port_mappings = [
        {
          name          = local.container_name
          containerPort = local.container_port
          protocol      = "tcp"
        }
      ]

      environment = [{
        name  = "DJANGO_SECRET_KEY",
        value = random_password.django_secret_key.result
        },
        {
          name  = "DJANGO_LOG_LEVEL",
          value = "INFO"
        },
        {
          name = "CSRF_TRUSTED_ORIGINS",
          value = "https://${local.dns}"
        },
        {
          name = "REDIS_URL"
          value = "redis://cache.csb5vn.0001.euw2.cache.amazonaws.com:6379"	
        },
        {
          name  = "DJANGO_SETTINGS_MODULE",
          value = "cointranet.settings.base"
        },
        {
          name  = "WAGTAILADMIN_BASE_URL",
          value = "wagtail-poc.codatt.net"
        },
        {
          name  = "DATABASE_URL",
          value = "postgres://wagtail:${random_password.application_password.result}@${null_resource.postgres.triggers.endpoint}/wagtail"
        },
        {
          name  = "ADMIN_EMAIL",
          value = local.admin_email
        },
        {
          name  = "ADMIN_PASSWORD",
          value = random_password.admin_password.result
        },
        {
          name  = "AWS_STORAGE_BUCKET_NAME",
          value = module.s3_bucket.s3_bucket_id
        },
        {
          name  = "AWS_ACCESS_KEY_ID",
          value = aws_iam_access_key.wagtail.id
        },
        {
          name  = "AWS_SECRET_ACCESS_KEY",
          value = aws_iam_access_key.wagtail.secret # TODO: don't put this in environment and add some aws secret manage access from wagtail          
        },
        {
          name = "AWS_S3_VPCE_DNS",
          value = "s3.eu-west-2.amazonaws.com"
        }
      ]

      # Example image used requires access to write to root filesystem
      readonly_root_filesystem = false
    }
  }

  load_balancer = {
    service = {
      target_group_arn = element(module.alb.target_group_arns, 0)
      container_name   = local.container_name
      container_port   = local.container_port
    }
  }

  subnet_ids = module.vpc.private_subnets
  security_group_rules = {
    alb_http_ingress = {
      type                     = "ingress"
      from_port                = local.container_port
      to_port                  = local.container_port
      protocol                 = "tcp"
      description              = "Service port"
      source_security_group_id = module.alb_sg.security_group_id
    }
    db_egress_all = {
      type        = "egress"
      from_port   = 5432
      to_port     = 5432
      protocol    = "tcp"
      cidr_blocks = module.vpc.database_subnets_cidr_blocks
    }
    s3_egress_all = {
      type        = "egress"
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = data.aws_ip_ranges.s3_ranges.cidr_blocks
    }
    redis_egress_all = {
      type        = "egress"
      from_port   = 6379
      to_port     = 6379
      protocol    = "tcp"
      cidr_blocks = module.vpc.private_subnets_cidr_blocks
    }
  }

  tags = local.tags
}

module "ecs_scheduled_task" {
  source                = "git::https://github.com/tmknom/terraform-aws-ecs-scheduled-task.git?ref=tags/2.0.0"
  name                  = "content"
  schedule_expression   = "rate(2 minutes)"
  cluster_arn           = module.ecs_cluster.cluster_arn
  subnets               = module.vpc.private_subnets
  security_groups       = [module.autoscaling_sg.security_group_id]
  ecs_task_execution_role_arn = module.ecs_service.task_exec_iam_role_arn

    container_definitions = jsonencode([
    {
      name      = "publish_scheduled_articles"
      image     = "${local.account_id}.dkr.ecr.${local.region}.amazonaws.com/${local.name}:latest"
      environment = [{
              name  = "DJANGO_SECRET_KEY",
        value = random_password.django_secret_key.result
        },
        {
          name  = "DJANGO_LOG_LEVEL",
          value = "INFO"
        },
        {
          name  = "DJANGO_SETTINGS_MODULE",
          value = "cointranet.settings.base"
        },
        {
          name  = "DATABASE_URL",
          value = "postgres://wagtail:${random_password.application_password.result}@${null_resource.postgres.triggers.endpoint}/wagtail"
        }]
              logConfiguration = {
        logDriver = "awslogs"
        options = {
        awslogs-stream-prefix = "content-scheduler"
        awslogs-group         = "/aws/ecs/${local.name}"
        awslogs-region        = local.region
        awslogs-create-group = "true"
        }
      }
      
      essential = true
      command = ["-v", "3"]
      entrypoint = ["/venv/bin/python","manage.py","publish_scheduled"]
    }
  ])
}

################################################################################
# Supporting Resources
################################################################################

# https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-optimized_AMI.html#ecs-optimized-ami-linux
data "aws_ssm_parameter" "ecs_optimized_ami" {
  name = "/aws/service/ecs/optimized-ami/amazon-linux-2/recommended"
}

module "alb_sg" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 5.0"

  name        = "${local.name}-service"
  description = "Service security group"
  vpc_id      = module.vpc.vpc_id

  ingress_rules       = ["http-80-tcp", "https-443-tcp"]
  ingress_cidr_blocks = local.allowed_ip_ranges

  egress_rules       = ["all-all"]
  egress_cidr_blocks = module.vpc.public_subnets_cidr_blocks

  tags = local.tags
}

module "alb" {
  source  = "terraform-aws-modules/alb/aws"
  version = "~> 8.0"

  name = local.name

  load_balancer_type = "application"

  vpc_id          = module.vpc.vpc_id
  subnets         = module.vpc.public_subnets
  security_groups = [module.alb_sg.security_group_id, module.autoscaling_sg.security_group_id]
  preserve_host_header = true
  enable_http2 = false

  https_listeners = [
    {
      port               = 443
      protocol           = "HTTPS"
      certificate_arn    = local.acm_certificate_arn # TODO: make this dynamic
      target_group_index = 0
    }
  ]

  target_groups = [
    {
      name             = substr("${local.name}-${local.container_name}", 0, 32)
      backend_protocol = "HTTP"
      backend_port     = local.container_port
      target_type      = "ip"
    },
  ]

  access_logs = {
    bucket = module.log_bucket.s3_bucket_id
  }

  tags = local.tags
}

#module "zones" {
#  source  = "terraform-aws-modules/route53/aws//modules/zones"
#  version = "~> 2.0"
#
#  zones = {
#    (local.dns) = {
#      comment = "wagtail intranet zone - ${local.workspace} - ${local.name}"
#      tags = local.tags
#    }
#  }
#
#  tags = local.tags
#}


#module "acm" {
#  source  = "terraform-aws-modules/acm/aws"
#  version = "~> 4.0"
#
#  domain_name  = local.dns
#  zone_id      = module.zones.route53_zone_zone_id[local.dns]
#
#  validation_method = "EMAIL"
#
#  wait_for_validation = true
#
#  tags = local.tags
#}

module "autoscaling" {
  source  = "terraform-aws-modules/autoscaling/aws"
  version = "~> 6.5"

  for_each = {
    # Intranet
    intranet = {
      instance_type              = "t3.large"
      use_mixed_instances_policy = false
      mixed_instances_policy     = {}
      user_data                  = <<-EOT
        #!/bin/bash
        cat <<'EOF' >> /etc/ecs/ecs.config
        ECS_CLUSTER=${local.name}
        ECS_LOGLEVEL=debug
        ECS_CONTAINER_INSTANCE_TAGS=${jsonencode(local.tags)}
        ECS_ENABLE_TASK_IAM_ROLE=true
        EOF
      EOT
    }
  }

  name = "${local.name}-${each.key}"

  image_id      = jsondecode(data.aws_ssm_parameter.ecs_optimized_ami.value)["image_id"]
  instance_type = each.value.instance_type

  security_groups                 = [module.autoscaling_sg.security_group_id]
  user_data                       = base64encode(each.value.user_data)
  ignore_desired_capacity_changes = true

  create_iam_instance_profile = true
  iam_role_name               = local.name
  iam_role_description        = "ECS role for ${local.name}"
  iam_role_policies = {
    AmazonEC2ContainerServiceforEC2Role = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
    AmazonSSMManagedInstanceCore        = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  }

  vpc_zone_identifier = module.vpc.private_subnets
  health_check_type   = "EC2"
  min_size            = 1
  max_size            = 2
  desired_capacity    = 1

  # https://github.com/hashicorp/terraform-provider-aws/issues/12582
  autoscaling_group_tags = {
    AmazonECSManaged = true
  }

  # Required for  managed_termination_protection = "ENABLED"
  protect_from_scale_in = true

  # Spot instances
  use_mixed_instances_policy = each.value.use_mixed_instances_policy
  mixed_instances_policy     = each.value.mixed_instances_policy

  tags = local.tags
}

module "autoscaling_sg" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 5.0"

  name        = local.name
  description = "Autoscaling group security group"
  vpc_id      = module.vpc.vpc_id

  computed_ingress_with_source_security_group_id = [
    {
      rule                     = "http-80-tcp"
      source_security_group_id = module.alb_sg.security_group_id
    },
    {
      rule                     = "http-8080-tcp"
      source_security_group_id = module.alb_sg.security_group_id
    }
  ]
  number_of_computed_ingress_with_source_security_group_id = 2

  egress_rules = ["all-all"]

  tags = local.tags
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
#  version = "~> 5.0"
  version = "5.1.2"

  name = local.name
  cidr = local.vpc_cidr

  azs              = local.azs
  private_subnets  = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 4, k)]
  public_subnets   = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 8, k + 48)]
  database_subnets = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 8, k + 56)]

  enable_nat_gateway = true
  single_nat_gateway = true
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = local.tags
}

################################################################################
# VPC Endpoints Module
################################################################################

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = module.vpc.vpc_id
  service_name      = "com.amazonaws.eu-west-2.s3"
  vpc_endpoint_type = "Interface"

  security_group_ids = [module.autoscaling_sg.security_group_id]
  subnet_ids = module.vpc.private_subnets
#  route_table_ids = module.vpc.private_route_table_ids
#  private_dns_enabled = true
}

module "ecr" {
  source = "terraform-aws-modules/ecr/aws"

  repository_name                 = local.name
  repository_type                 = "private"
  repository_image_tag_mutability = "MUTABLE"

  repository_read_write_access_arns = [aws_iam_role.docker_ci.arn]
  repository_lifecycle_policy = jsonencode({
    rules = [
      {
        rulePriority = 1,
        description  = "Keep last 30 images",
        selection = {
          tagStatus     = "tagged",
          tagPrefixList = ["v"],
          countType     = "imageCountMoreThan",
          countNumber   = 30
        },
        action = {
          type = "expire"
        }
      }
    ]
  })

  tags = local.tags
}

################################################################################
# Continuous integration
################################################################################

resource "aws_codestarconnections_connection" "github" {
  name          = "github-${terraform.workspace}"
  provider_type = "GitHub"
}

data "aws_iam_policy_document" "terraform_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["codebuild.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "terraform_ci" {
  name               = "terraform_ci"
  assume_role_policy = data.aws_iam_policy_document.terraform_assume_role.json
}

data "aws_iam_policy_document" "terraform_ci" {
  statement {
    effect = "Allow"
    actions = [
      "codestar-connections:UseConnection",
      "codestar-connections:GetConnection",
      "codestar-connections:ListTagsForResource",
    ]
    resources = [aws_codestarconnections_connection.github.arn]
  }

  statement {
    effect = "Allow"

    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    resources = ["*"]
  }

  statement {
    effect = "Allow"

    actions = [
      "s3:*",
      "iam:*",
      "logs:*",
      "codebuild:*",
      "ec2:*",
      "ecs:*",
      "ecr:*",
      "ssm:Get*",
      "autoscaling:*",
      "elasticloadbalancing:*",
      "application-autoscaling:*",
      "rds:*",
      "secretsmanager:*",
      "kms:*",
      "elasticache:*",
      "events:*"
    ]

    resources = ["*"] # TODO: lock this down to the bucket that is in use for state
  }

}

resource "aws_iam_role_policy" "terraform_ci" {
  role   = aws_iam_role.terraform_ci.name
  policy = data.aws_iam_policy_document.terraform_ci.json
}

resource "aws_codebuild_project" "terraform_ci" {
  name          = "${local.name}-terraform"
  description   = "terraform builds"
  build_timeout = "5"
  service_role  = aws_iam_role.terraform_ci.arn

  artifacts {
    type = "NO_ARTIFACTS"
  }

  cache {
    type = "NO_CACHE"
  }

  environment {
    compute_type                = "BUILD_GENERAL1_SMALL"
    image                       = "registry-1.docker.io/hashicorp/terraform:1.4"
    type                        = "LINUX_CONTAINER"
    image_pull_credentials_type = "CODEBUILD"

    environment_variable {
      name  = "REPOSITORY_URL"
      value = module.ecr.repository_url
    }

    environment_variable {
      name  = "DEFAULT_AWS_REGION"
      value = local.region
    }
  }

  source {
    type            = "GITHUB"
    location        = "https://github.com/cabinetoffice/cointranet-infra.git"
    git_clone_depth = 1

    git_submodules_config {
      fetch_submodules = true
    }
  }

  vpc_config {
    vpc_id             = module.vpc.vpc_id
    subnets            = module.vpc.private_subnets
    security_group_ids = [module.autoscaling_sg.security_group_id]
  }

  source_version = "main"

  tags = local.tags
}


resource "aws_codebuild_webhook" "terraform_ci" {
  project_name = aws_codebuild_project.terraform_ci.name
  build_type   = "BUILD"
  filter_group {
    filter {
      type    = "EVENT"
      pattern = "PUSH"
    }
  }
}

data "aws_iam_policy_document" "docker_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["codebuild.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "docker_ci" {
  name               = "docker_ci"
  assume_role_policy = data.aws_iam_policy_document.docker_assume_role.json
}

data "aws_iam_policy_document" "docker_ci" {
  statement {
    effect    = "Allow"
    actions   = ["codestar-connections:UseConnection"]
    resources = [aws_codestarconnections_connection.github.arn]
  }

  statement {
    effect = "Allow"

    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    resources = ["*"]
  }

  statement {
    effect = "Allow"

    actions = [
      "ecr:*",
    ]

    resources = ["*"]
  }
}

resource "aws_iam_role_policy_attachment" "docker_ci" {
  role       = aws_iam_role.docker_ci.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryPowerUser"
}

resource "aws_iam_role_policy" "docker_ci" {
  role   = aws_iam_role.docker_ci.name
  policy = data.aws_iam_policy_document.docker_ci.json
}

resource "aws_codebuild_project" "docker_ci" {
  name          = "${local.name}-docker"
  description   = "docker builds"
  build_timeout = "5"
  service_role  = aws_iam_role.docker_ci.arn

  artifacts {
    type = "NO_ARTIFACTS"
  }

  cache {
    type = "NO_CACHE"
  }

  environment {
    compute_type                = "BUILD_GENERAL1_SMALL"
    image                       = "aws/codebuild/standard:5.0"
    type                        = "LINUX_CONTAINER"
    image_pull_credentials_type = "CODEBUILD"
    privileged_mode             = true

    environment_variable {
      name  = "REPOSITORY_URL"
      value = "${local.account_id}.dkr.ecr.${local.region}.amazonaws.com/${local.name}"
    }

    environment_variable {
      name  = "DEFAULT_AWS_REGION"
      value = local.region
    }
    environment_variable {
      name  = "AWS_ACCOUNT_ID"
      value = local.account_id
    }

    environment_variable {
      name  = "IMAGE_TAG"
      value = "latest"
    }
  }

  source {
    type            = "GITHUB"
    location        = "https://github.com/cabinetoffice/co-wagtail-base.git" # TODO: parameterise based on forks
    git_clone_depth = 1

    git_submodules_config {
      fetch_submodules = true
    }
  }

  source_version = "main"

  tags = local.tags
}

resource "aws_codebuild_webhook" "docker_ci" {
  project_name = aws_codebuild_project.docker_ci.name
  build_type   = "BUILD"
  filter_group {
    filter {
      type    = "EVENT"
      pattern = "PUSH"
    }
  }
}

################################################################################
# RDS / PostgresQL
################################################################################

module "db_sg" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 5.0"

  name        = "${local.name}-ci"
  description = "DB security group"
  vpc_id      = module.vpc.vpc_id

  computed_ingress_with_source_security_group_id = [
    {
      rule                     = "postgresql-tcp"
      source_security_group_id = module.autoscaling_sg.security_group_id # TODO: this is CI, make a dedicated sg
    },
    {
      rule                     = "postgresql-tcp"
      source_security_group_id = module.ecs_service.security_group_id # wagtail
    }
  ]
  number_of_computed_ingress_with_source_security_group_id = 2

  egress_rules = ["all-all"]

  tags = local.tags
}

#resource "aws_iam_role_policy_attachment" "postgres_iam" {
#  role   = module.ecs.task_exec_iam_role_arn
#  policy_arn = "arn:aws:iam::aws:policy/"
#}

resource "postgresql_role" "application_role" {
  name               = "wagtail"
  login              = true
  password           = random_password.application_password.result
  encrypted_password = true
  depends_on         = [module.db]
}

module "db" {
  source = "terraform-aws-modules/rds/aws"

  identifier          = "rds-${local.name}"
  publicly_accessible = false

  engine               = "postgres"
  engine_version       = "14"
  family               = "postgres14"   # DB parameter group
  major_engine_version = "14"           # DB option group
  instance_class       = "db.t4g.micro" # TODO: is this correctly sized? 

  allocated_storage     = 20
  max_allocated_storage = 100

  db_name                     = "wagtail" # TODO: this needs to be unique but can only contain alphanumeric characters
  username                    = "admin_user"
  manage_master_user_password = true
  port                        = 5432

  multi_az               = true
  db_subnet_group_name   = module.vpc.database_subnet_group
  vpc_security_group_ids = [module.db_sg.security_group_id] # [module.alb_sg.security_group_id,module.autoscaling_sg.security_group_id]

  maintenance_window              = "Mon:00:00-Mon:03:00"
  backup_window                   = "03:00-06:00"
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
  create_cloudwatch_log_group     = true

  backup_retention_period = 1
  skip_final_snapshot     = true
  deletion_protection     = false

  performance_insights_enabled          = true
  performance_insights_retention_period = 7
  create_monitoring_role                = true
  monitoring_interval                   = 60
  monitoring_role_name                  = "${local.name}-monitoring"
  monitoring_role_use_name_prefix       = true
  monitoring_role_description           = "${local.name} postgres monitoring role"

  parameters = [
    {
      name  = "autovacuum"
      value = 1
    },
    {
      name  = "client_encoding"
      value = "utf8"
    }
  ]

  tags = local.tags
  db_option_group_tags = {
    "Sensitive" = "low"
  }
  db_parameter_group_tags = {
    "Sensitive" = "low"
  }
}

################################################################################
# S3
################################################################################

resource "aws_kms_key" "bucket" {
  description             = "Wagtail bucket key for ${local.name}"
  deletion_window_in_days = 7
}

resource "aws_iam_role" "bucket" {
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

data "aws_iam_policy_document" "bucket" {
  statement {
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.bucket.arn, aws_iam_user.wagtail.arn]
    }

    actions = [
      "s3:ListBucket",
    ]

    resources = [
      "arn:aws:s3:::${local.name}-${local.account_id}-${local.workspace}",
    ]
  }
  
  statement {
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.bucket.arn, aws_iam_user.wagtail.arn]
    }

    actions = [
      "s3:*",
    ]

    resources = [
      "arn:aws:s3:::${local.name}-${local.account_id}-${local.workspace}/*",
    ]
  }
  
  statement {
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions = [
      "s3:Get*",
    ]

    resources = [
      "arn:aws:s3:::${local.name}-${local.account_id}-${local.workspace}/*",
    ]

    condition {
      test  = "IpAddress"
      variable = "aws:SourceIP" 
      values = local.allowed_ip_ranges
    }
  }
}

module "s3_bucket" {
  source = "terraform-aws-modules/s3-bucket/aws"

  bucket = "${local.name}-${local.account_id}-${local.workspace}" # name, account number, workspace

  force_destroy       = true
  acceleration_status = "Suspended"
  #request_payer       = "BucketOwner"

  tags = local.tags

  # Bucket policies
  attach_policy                         = true
  policy                                = data.aws_iam_policy_document.bucket.json
  attach_deny_insecure_transport_policy = false
  attach_require_latest_tls_policy      = false
  #  attach_deny_incorrect_encryption_headers = true
  #  attach_deny_incorrect_kms_key_sse        = true
  # allowed_kms_key_arn = aws_kms_key.bucket.arn
  #  attach_deny_unencrypted_object_uploads   = true
   block_public_acls = false
   block_public_policy = false
   ignore_public_acls = false
   restrict_public_buckets = false

  # S3 Bucket Ownership Controls
  # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_ownership_controls
  control_object_ownership = true
  object_ownership         = "BucketOwnerPreferred"

  expected_bucket_owner = local.account_id

  acl = "public-read" # "acl" conflicts with "grant" and "owner"
}

module "log_bucket" {
  source = "terraform-aws-modules/s3-bucket/aws"

  bucket_prefix = "${local.name}-logs-"
  acl           = "log-delivery-write"

  # For example only
  force_destroy = true

  control_object_ownership = true
  object_ownership         = "ObjectWriter"

  attach_elb_log_delivery_policy = true # Required for ALB logs
  attach_lb_log_delivery_policy  = true # Required for ALB/NLB logs

  attach_deny_insecure_transport_policy = true
  attach_require_latest_tls_policy      = true

  tags = local.tags
}


#
# Wagtail auth
#

data "aws_iam_policy_document" "wagtail_media" {
  statement {
    sid = "ListObjectsInBucket"
    actions = [
      "s3:ListBucket",
    ]

    resources = [
      "arn:aws:s3:::${module.s3_bucket.s3_bucket_id}",
    ]
  }

  statement {
    sid = "AllObjectActions"

    actions = [
      "s3:*",
    ]

    resources = [
      "arn:aws:s3:::${module.s3_bucket.s3_bucket_id}/*",
    ]
  }
}

resource "aws_iam_access_key" "wagtail" {
  user = aws_iam_user.wagtail.name
}

resource "aws_iam_user" "wagtail" {
  name = "wagtail_media_uploader"
  path = "/robots/"
}

resource "aws_iam_user_policy" "wagtail" {
  name   = "wagtail"
  user   = aws_iam_user.wagtail.name
  policy = data.aws_iam_policy_document.wagtail_media.json
}

#
# Redis
#

resource "aws_elasticache_cluster" "cache" {
  cluster_id           = "cache"
  engine               = "redis"
  node_type            = "cache.t4g.micro"
  num_cache_nodes      = 1
  parameter_group_name = "default.redis6.x"
  subnet_group_name = aws_elasticache_subnet_group.cache.name
  engine_version       = "6.2"
  port                 = 6379
}

resource "aws_elasticache_subnet_group" "cache" {
  name       = "cache"
  subnet_ids = module.vpc.private_subnets
}
