# Data-plane checks for the live proof: something to send requests through
# the web ACL, and a function inside the VPC that connects to the hardened
# database. dataplane_probe.py drives both and pushes an image to ECR.
#
# Build the function package first: ./dataplane/build.sh

# --- A target for the web ACL -------------------------------------------------

# A REST API with one mock method. It has no backend, so the only thing a
# request can reach is the web ACL in front of it.
resource "aws_api_gateway_rest_api" "waf_target" {
  #checkov:skip=CKV_AWS_237: Proof fixture, replaced on every run.
  name = "${local.name}-waf-target"

  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

resource "aws_api_gateway_method" "waf_target" {
  #checkov:skip=CKV_AWS_59: Proof fixture with a mock integration; the web ACL is what is under test.
  #checkov:skip=CKV2_AWS_53: Proof fixture with a mock integration.
  rest_api_id   = aws_api_gateway_rest_api.waf_target.id
  resource_id   = aws_api_gateway_rest_api.waf_target.root_resource_id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "waf_target" {
  rest_api_id = aws_api_gateway_rest_api.waf_target.id
  resource_id = aws_api_gateway_rest_api.waf_target.root_resource_id
  http_method = aws_api_gateway_method.waf_target.http_method
  type        = "MOCK"

  request_templates = {
    "application/json" = jsonencode({ statusCode = 200 })
  }
}

resource "aws_api_gateway_method_response" "waf_target" {
  rest_api_id = aws_api_gateway_rest_api.waf_target.id
  resource_id = aws_api_gateway_rest_api.waf_target.root_resource_id
  http_method = aws_api_gateway_method.waf_target.http_method
  status_code = "200"
}

resource "aws_api_gateway_integration_response" "waf_target" {
  rest_api_id = aws_api_gateway_rest_api.waf_target.id
  resource_id = aws_api_gateway_rest_api.waf_target.root_resource_id
  http_method = aws_api_gateway_method.waf_target.http_method
  status_code = aws_api_gateway_method_response.waf_target.status_code

  depends_on = [aws_api_gateway_integration.waf_target]
}

resource "aws_api_gateway_deployment" "waf_target" {
  rest_api_id = aws_api_gateway_rest_api.waf_target.id

  depends_on = [aws_api_gateway_integration_response.waf_target]

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_api_gateway_stage" "waf_target" {
  #checkov:skip=CKV_AWS_73: Proof fixture, lives for one run.
  #checkov:skip=CKV_AWS_76: Proof fixture, lives for one run. The web ACL's own log is what the probe reads.
  #checkov:skip=CKV_AWS_120: Proof fixture, lives for one run.
  #checkov:skip=CKV2_AWS_4: Proof fixture, lives for one run.
  #checkov:skip=CKV2_AWS_51: Proof fixture, lives for one run.
  rest_api_id   = aws_api_gateway_rest_api.waf_target.id
  deployment_id = aws_api_gateway_deployment.waf_target.id
  stage_name    = "proof"
}

resource "aws_wafv2_web_acl_association" "waf_target" {
  resource_arn = aws_api_gateway_stage.waf_target.arn
  web_acl_arn  = module.waf_hardened.web_acl_arn
}

# --- A database client inside the VPC -----------------------------------------

locals {
  db_host      = split(":", module.rds_postgres_hardened.db_instance_endpoint)[0]
  db_iam_user  = "proof_iam"
  db_client    = "${local.name}-db-client"
  db_resource  = "arn:${data.aws_partition.current.partition}:rds-db:${var.region}:${data.aws_caller_identity.current.account_id}:dbuser"
  secrets_keys = "arn:${data.aws_partition.current.partition}:kms:${var.region}:${data.aws_caller_identity.current.account_id}:key/*"
}

data "aws_db_instance" "hardened" {
  db_instance_identifier = "${local.name}-hardened"

  depends_on = [module.rds_postgres_hardened]
}

data "archive_file" "db_client" {
  type        = "zip"
  source_dir  = "${path.module}/dataplane/build"
  output_path = "${path.module}/dataplane/db-client.zip"
}

resource "aws_security_group" "db_client" {
  name        = local.db_client
  description = "Proof fixture: database client. PostgreSQL and TLS to the VPC only."
  vpc_id      = module.network_perimeter_vpc.vpc_id

  egress {
    description = "PostgreSQL to the database subnets"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.perimeter.cidr_block]
  }

  egress {
    description = "TLS to the interface endpoints"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.perimeter.cidr_block]
  }
}

resource "aws_iam_role" "db_client" {
  name = local.db_client

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
      Condition = { StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id } }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "db_client_vpc" {
  role       = aws_iam_role.db_client.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

resource "aws_iam_role_policy" "db_client" {
  name = "db-client"
  role = aws_iam_role.db_client.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadMasterSecret"
        Effect   = "Allow"
        Action   = "secretsmanager:GetSecretValue"
        Resource = module.rds_postgres_hardened.master_user_secret_arn
      },
      {
        Sid       = "DecryptMasterSecret"
        Effect    = "Allow"
        Action    = "kms:Decrypt"
        Resource  = local.secrets_keys
        Condition = { StringEquals = { "kms:ViaService" = "secretsmanager.${var.region}.amazonaws.com" } }
      },
      {
        Sid      = "ConnectAsIamUser"
        Effect   = "Allow"
        Action   = "rds-db:connect"
        Resource = "${local.db_resource}:${data.aws_db_instance.hardened.resource_id}/${local.db_iam_user}"
      },
    ]
  })
}

resource "aws_lambda_function" "db_client" {
  #checkov:skip=CKV_AWS_115: Proof fixture, invoked a handful of times in one run.
  #checkov:skip=CKV_AWS_116: Proof fixture, invoked synchronously; the caller sees every error.
  #checkov:skip=CKV_AWS_173: Proof fixture. The environment holds a hostname and an ARN, no secrets.
  #checkov:skip=CKV_AWS_272: Proof fixture, lives for one run.
  #checkov:skip=CKV_AWS_50: Proof fixture, lives for one run.
  function_name    = local.db_client
  role             = aws_iam_role.db_client.arn
  runtime          = "python3.12"
  handler          = "handler.handler"
  filename         = data.archive_file.db_client.output_path
  source_code_hash = data.archive_file.db_client.output_base64sha256
  timeout          = 120
  memory_size      = 256

  vpc_config {
    subnet_ids         = module.network_perimeter_vpc.application_subnet_ids
    security_group_ids = [aws_security_group.db_client.id]
  }

  environment {
    variables = {
      DB_HOST     = local.db_host
      DB_IAM_USER = local.db_iam_user
      SECRET_ARN  = module.rds_postgres_hardened.master_user_secret_arn
    }
  }

  depends_on = [aws_iam_role_policy_attachment.db_client_vpc, module.fips_vpc_endpoints]
}

output "dataplane" {
  description = "What dataplane_probe.py needs."
  value = {
    region         = var.region
    ecr_repository = local.name
    waf_target_url = aws_api_gateway_stage.waf_target.invoke_url
    waf_log_group  = "aws-waf-logs-${local.name}"
    db_client      = aws_lambda_function.db_client.function_name
  }
}
