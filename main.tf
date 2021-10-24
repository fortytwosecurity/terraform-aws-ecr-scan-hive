

resource "random_string" "hive_api_key" {
  length = 4
}

module "hive_api_key" {
  source  = "QuiNovas/standard-secret/aws"
  version = "3.0.2"
  name    = "test/hive/api-key-${random_string.hive_api_key.id}"
}

module "hive_ecr_cloudwatch_event" {
  source = "git::https://github.com/cloudposse/terraform-aws-cloudwatch-events.git?ref=master"
  name   = "hive_ecr_cloudwatch-${random_string.server.id}"

  cloudwatch_event_rule_description = var.cloudwatch_event_rule_description
  cloudwatch_event_rule_pattern     = var.cloudwatch_event_rule_pattern
  cloudwatch_event_target_arn       = module.ecr_to_hive_lambda.lambda_function_arn
}

module "hive_ecr_iam_assumable_role" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-assumable-role"
  version = "~> 3.0"

  trusted_role_services = [
    "lambda.amazonaws.com"
  ]

  create_role = true

  role_name         = "ECRToHiveFindingsLambdaRole-${random_string.server.id}"
  role_requires_mfa = false

  custom_role_policy_arns = [
    module.hive_ecr_iam_policy.arn
  ]
}

module "hive_ecr_iam_policy" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-policy"
  version = "~> 3.0"

  name        = "ECRToHiveFindingsLambda-Policy-${random_string.server.id}"
  path        = "/"
  description = "ECRToHiveFindingsLambda-Policy"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "cloudwatch:PutMetricData"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }, 
    {
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Effect": "Allow",
      "Resource": "*"
    },
    { 
      "Action": [
        "secretsmanager:GetSecretValue"
      ],
      "Effect": "Allow",
      "Resource": "${module.hive_api_key.arn}"
    },
        { 
      "Action": [
        "kms:Decrypt"
      ],
      "Effect": "Allow",
      "Resource": "${module.hive_api_key.kms_key_arn}"
    }       
  ]
}
EOF
}

resource "aws_lambda_permission" "hive_ecr_allow_cloudwatch" {
  statement_id  = "PermissionForEventsToInvokeLambdachk-${random_string.server.id}"
  action        = "lambda:InvokeFunction"
  function_name = module.ecr_to_hive_lambda.lambda_function_name
  principal     = "events.amazonaws.com"
  source_arn    = module.hive_ecr_cloudwatch_event.aws_cloudwatch_event_rule_arn
}

data "archive_file" "ecr_to_hive_lambda_zip" {
  type        = "zip"
  source_file = "lambda_ecr_hive.py"
  output_path = "lambda_ecr_hive.zip"
}

module "thehive4py_layer" {
  source  = "terraform-aws-modules/lambda/aws"
  version = "2.7.0"

  create_layer = true

  layer_name          = "thehive4py-layer-local"
  description         = "Lambda layer containing thehive4py"
  compatible_runtimes = ["python3.8"]

  create_package         = false
  local_existing_package = "${path.module}/layer.zip"

  #ignore_source_code_hash = true
}

module "ecr_to_hive_lambda" {
  source  = "terraform-aws-modules/lambda/aws"
  version = "2.7.0"

  function_name  = "ecrscan-to-hive"
  description    = "function to send ecr scan finding to the hive"
  handler        = "lambda_ecr_hive.lambda_handler"
  runtime        = "python3.8"
  create_package = false

  local_existing_package = "lambda_ecr_hive.zip"

  environment_variables = {
    hiveSecretArn = module.hive_api_key.arn
  }

  layers = [
    module.thehive4py_layer.lambda_layer_arn,
  ]
  
  attach_policies    = true
  policies           = [module.hive_ecr_iam_policy.arn]
  number_of_policies = 1

}
