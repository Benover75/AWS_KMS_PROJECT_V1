# KMS Key with enhanced security and monitoring
resource "aws_kms_key" "app_key" {
  description                    = "KMS key for ${var.environment} environment"
  key_usage                      = var.key_usage
  customer_master_key_spec       = var.customer_master_key_spec
  enable_key_rotation            = var.enable_key_rotation
  deletion_window_in_days        = var.deletion_window_in_days
  pending_window_in_days         = var.pending_window_in_days
  is_enabled                     = true
  enable_key_rotation            = true
  
  # Policy based on environment
  policy = var.environment == "production" ? 
    file("${path.module}/../config/prod/kms-policy.json") : 
    file("${path.module}/../config/dev/kms-policy.json")
  
  tags = merge(var.tags, {
    Name = "${var.environment}-kms-key"
  })
}

# KMS Alias for easier reference
resource "aws_kms_alias" "app_key_alias" {
  name          = var.alias
  target_key_id = aws_kms_key.app_key.key_id
}

# CloudWatch Log Group for KMS monitoring
resource "aws_cloudwatch_log_group" "kms_logs" {
  name              = "/aws/kms/${var.environment}"
  retention_in_days = 30
  
  tags = var.tags
}

# CloudWatch Alarm for KMS usage
resource "aws_cloudwatch_metric_alarm" "kms_usage_alarm" {
  count               = var.environment == "production" ? 1 : 0
  alarm_name          = "${var.environment}-kms-usage-alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "NumberOfRequests"
  namespace           = "AWS/KMS"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1000"
  alarm_description   = "KMS usage threshold exceeded"
  
  dimensions = {
    KeyId = aws_kms_key.app_key.key_id
  }
  
  tags = var.tags
}

# IAM Role for KMS encryption operations
resource "aws_iam_role" "kms_encrypt_role" {
  name = "${var.environment}-kms-encrypt-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
  
  tags = var.tags
}

# IAM Policy for encryption operations
resource "aws_iam_policy" "kms_encrypt_policy" {
  name        = "${var.environment}-kms-encrypt-policy"
  description = "Policy for KMS encryption operations"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:GenerateDataKey",
          "kms:GenerateDataKeyWithoutPlaintext",
          "kms:ReEncrypt*",
          "kms:DescribeKey"
        ]
        Resource = aws_kms_key.app_key.arn
      }
    ]
  })
}

# Attach policy to role
resource "aws_iam_role_policy_attachment" "kms_encrypt_policy_attachment" {
  role       = aws_iam_role.kms_encrypt_role.name
  policy_arn = aws_iam_policy.kms_encrypt_policy.arn
}

# IAM Role for KMS decryption operations
resource "aws_iam_role" "kms_decrypt_role" {
  name = "${var.environment}-kms-decrypt-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
  
  tags = var.tags
}

# IAM Policy for decryption operations
resource "aws_iam_policy" "kms_decrypt_policy" {
  name        = "${var.environment}-kms-decrypt-policy"
  description = "Policy for KMS decryption operations"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = aws_kms_key.app_key.arn
      }
    ]
  })
}

# Attach policy to role
resource "aws_iam_role_policy_attachment" "kms_decrypt_policy_attachment" {
  role       = aws_iam_role.kms_decrypt_role.name
  policy_arn = aws_iam_policy.kms_decrypt_policy.arn
}
