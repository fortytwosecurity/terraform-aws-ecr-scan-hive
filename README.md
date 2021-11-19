# Terraform Aws Ecr Scan Hive

Add secret separately.

```
resource "aws_kms_key" "hive_api_key_kms" {
  description         = "Key for secret hive_api_key"
  enable_key_rotation = true
}

resource "aws_kms_alias" "hive_api_key_kms" {
  name          = "alias/hive_api_key"
  target_key_id = aws_kms_key.hive_api_key_kms.key_id
}

resource "aws_secretsmanager_secret" "hive_api_key" {
  description = "The Hive url and api key"
  kms_key_id  = aws_kms_key.hive_api_key_kms.key_id
  name        = "root/hive/api-key"
}
```

secret value:

```
{
  "url": "https://hive.domain.com",
  "apikey": "putapikeyhere"
}
```
