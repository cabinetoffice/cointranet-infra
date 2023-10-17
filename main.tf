#
# Miscellaneous resources and settings
#

terraform {
  backend "s3" {
    bucket = "co-digital-proof-of-concepts-tfstate"
    key    = "terraform/dev"
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

data "aws_availability_zones" "available" {}
data "aws_caller_identity" "current" {}
data "aws_secretsmanager_secret_version" "postgres_password" {
  secret_id = module.db.db_instance_master_user_secret_arn
}

locals {
  region     = "eu-west-2"
  name       = basename(path.cwd)
  account_id = data.aws_caller_identity.current.account_id

  vpc_cidr = "10.0.0.0/16" # TODO: do we definitely need these to be unique?
  azs      = slice(data.aws_availability_zones.available.names, 0, 3)

  container_name = "wagtail"
  container_port = 8000

  codestar = "arn:aws:codestar-connections:eu-west-2:527922690890:connection/d277085d-2da1-4954-9143-93f7db172ea0"

  tags = {
    Name = local.name
  }
}

################################################################################
# Cluster
################################################################################

module "ecs_cluster" {
  source = "terraform-aws-modules/ecs/aws" # TODO: tag at version

  cluster_name = local.name

  default_capacity_provider_use_fargate = false
  autoscaling_capacity_providers = {
    intranet = {
      auto_scaling_group_arn         = module.autoscaling["intranet"].autoscaling_group_arn
      managed_termination_protection = "ENABLED"

      managed_scaling = {
        maximum_scaling_step_size = 5
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

  # Container definition(s)
  container_definitions = {
    (local.container_name) = {
      image = "${local.account_id}.dkr.ecr.${local.region}.amazonaws.com/${local.name}" # TODO: use a real image!
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
          name  = "DJANGO_SETTINGS_MODULE",
          value = "cointranet.settings.dev"
        },
        {
          name  = "DATABASE_URL",
          value = "postgres://admin_user:${random_password.application_password.result}@${null_resource.postgres.triggers.host}:${null_resource.postgres.triggers.port}/wagtail"
        }
      ]

      #entry_point = ["/usr/sbin/apache2", "-D", "FOREGROUND"] # TODO: use wagtail!

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
  security_group_ids = module.autoscaling_sg.security_group_ids # TODO: rework security groups and names
  security_group_rules = {
    alb_http_ingress = {
      type                     = "ingress"
      from_port                = local.container_port
      to_port                  = local.container_port
      protocol                 = "tcp"
      description              = "Service port"
      source_security_group_id = module.alb_sg.security_group_id
    }
  }

  tags = local.tags
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

  ingress_rules       = ["http-80-tcp"]
  ingress_cidr_blocks = ["0.0.0.0/0"]

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
  security_groups = [module.alb_sg.security_group_id]

  http_tcp_listeners = [
    {
      port               = local.container_port
      protocol           = "HTTP"
      target_group_index = 0
    },
  ]

  target_groups = [
    {
      name             = substr("${local.name}-${local.container_name}", 0, 32)
      backend_protocol = "HTTP"
      backend_port     = local.container_port
      target_type      = "ip"
    },
  ]

  tags = local.tags
}

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
  max_size            = 5
  desired_capacity    = 2

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
    }
  ]
  number_of_computed_ingress_with_source_security_group_id = 1

  egress_rules = ["all-all"]

  tags = local.tags
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = local.name
  cidr = local.vpc_cidr

  azs              = local.azs
  private_subnets  = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 4, k)]
  public_subnets   = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 8, k + 48)]
  database_subnets = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 8, k + 56)]

  enable_nat_gateway = true
  single_nat_gateway = true

  tags = local.tags
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

data "aws_codestarconnections_connection" "co" {
  arn = local.codestar
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
    resources = [data.aws_codestarconnections_connection.co.arn]
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
    resources = [data.aws_codestarconnections_connection.co.arn]
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
    location        = "https://github.com/cabinetoffice/co-wagtail-base.git"
    git_clone_depth = 1

    git_submodules_config {
      fetch_submodules = true
    }
  }

  source_version = "buildspec"

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
      source_security_group_id = module.autoscaling_sg.security_group_id
    }
  ]
  number_of_computed_ingress_with_source_security_group_id = 1

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

  identifier = "rds-${local.name}"

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
