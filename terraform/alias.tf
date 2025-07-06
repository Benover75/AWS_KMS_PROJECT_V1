resource "aws_kms_alias" "app_key_alias" {
  name          = var.alias
  target_key_id = aws_kms_key.app_key.key_id
}
