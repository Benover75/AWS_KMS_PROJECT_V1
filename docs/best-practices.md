# AWS KMS Best Practices

This document outlines best practices for using AWS KMS securely and efficiently in production environments.

## 🔒 Security Best Practices

### 1. IAM Policy Design

#### Principle of Least Privilege
- **Separate permissions by role**: Create distinct policies for admin, encrypt, and decrypt operations
- **Use specific actions**: Avoid wildcards (`kms:*`) in production policies
- **Implement conditions**: Use IAM conditions to restrict access based on context

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowEncryptOnly",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::123456789012:role/encrypt-role"},
      "Action": [
        "kms:Encrypt",
        "kms:GenerateDataKey",
        "kms:DescribeKey"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:RequestTag/Environment": "production"
        }
      }
    }
  ]
}
```

#### Key Rotation Policies
- **Enable automatic rotation**: Set `enable_key_rotation = true`
- **Monitor rotation status**: Check key rotation status regularly
- **Plan manual rotation**: Have procedures for manual key rotation when needed

### 2. Key Management

#### Key Lifecycle
- **Creation**: Use descriptive names and tags
- **Usage**: Monitor key usage patterns
- **Rotation**: Automate where possible
- **Archival**: Implement proper archival policies
- **Deletion**: Use appropriate deletion windows

#### Key Aliases
- **Use meaningful aliases**: `alias/prod-database-key` instead of `alias/key1`
- **Environment separation**: Different aliases for different environments
- **Version management**: Use aliases for key version management

### 3. Encryption Patterns

#### Envelope Encryption
Always use envelope encryption for data larger than 4KB:

```python
# Good: Envelope encryption for large data
def encrypt_large_file(file_path, key_id):
    # Generate data key
    response = kms.generate_data_key(KeyId=key_id, KeySpec='AES_256')
    plaintext_key = response['Plaintext']
    encrypted_key = response['CiphertextBlob']
    
    # Encrypt data locally
    cipher = AES.new(plaintext_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    
    return {
        'encrypted_key': encrypted_key,
        'ciphertext': ciphertext,
        'nonce': cipher.nonce,
        'tag': tag
    }
```

#### Encryption Context
Use encryption context for additional security:

```python
# Include encryption context
response = kms.encrypt(
    KeyId=key_id,
    Plaintext=data,
    EncryptionContext={
        'Environment': 'production',
        'Service': 'database',
        'DataClassification': 'confidential'
    }
)
```

### 4. Access Control

#### Cross-Account Access
- **Use IAM roles**: Instead of sharing keys across accounts
- **Implement cross-account policies**: Carefully design cross-account access
- **Monitor cross-account usage**: Track and audit cross-account access

#### Service Integration
- **Use service roles**: Let AWS services assume roles for KMS access
- **Implement resource policies**: Use resource-based policies when appropriate
- **Monitor service usage**: Track which services are using KMS keys

## ⚡ Performance Best Practices

### 1. Key Selection

#### Regional Distribution
- **Use regional keys**: Keep keys in the same region as your data
- **Consider latency**: Choose regions close to your application
- **Plan for disaster recovery**: Have keys in multiple regions

#### Key Types
- **Symmetric keys**: Use for most encryption/decryption operations
- **Asymmetric keys**: Use only when needed (signing, specific algorithms)
- **Custom key stores**: Consider for compliance requirements

### 2. Caching and Optimization

#### Data Key Caching
Implement data key caching for high-throughput applications:

```python
import time
from functools import lru_cache

class CachedKMSClient:
    def __init__(self, kms_client, cache_duration=300):
        self.kms_client = kms_client
        self.cache_duration = cache_duration
        self.cache = {}
    
    def generate_data_key(self, key_id, key_spec='AES_256'):
        cache_key = f"{key_id}:{key_spec}"
        now = time.time()
        
        if cache_key in self.cache:
            cached_data, timestamp = self.cache[cache_key]
            if now - timestamp < self.cache_duration:
                return cached_data
        
        # Generate new key
        response = self.kms_client.generate_data_key(KeyId=key_id, KeySpec=key_spec)
        self.cache[cache_key] = (response, now)
        return response
```

#### Batch Operations
Use batch operations when possible:

```python
# Batch encrypt multiple items
def batch_encrypt(items, key_id):
    encrypted_items = []
    for item in items:
        response = kms.encrypt(KeyId=key_id, Plaintext=item)
        encrypted_items.append(response['CiphertextBlob'])
    return encrypted_items
```

### 3. Error Handling

#### Retry Logic
Implement proper retry logic for KMS operations:

```python
import time
from botocore.exceptions import ClientError

def kms_operation_with_retry(operation, max_retries=3, backoff_factor=2):
    for attempt in range(max_retries):
        try:
            return operation()
        except ClientError as e:
            if e.response['Error']['Code'] in ['ThrottlingException', 'ServiceUnavailable']:
                if attempt < max_retries - 1:
                    sleep_time = backoff_factor ** attempt
                    time.sleep(sleep_time)
                    continue
            raise
```

## 📊 Monitoring and Alerting

### 1. Key Metrics

#### Essential Metrics
Monitor these key metrics:
- **Request count**: Number of KMS API calls
- **Error rate**: Percentage of failed requests
- **Latency**: Response time for KMS operations
- **Key usage**: Which keys are being used most
- **Cost**: KMS usage costs

#### CloudWatch Alarms
Set up alarms for:
- High error rates (>5%)
- Unusual usage spikes
- Key rotation failures
- Cost thresholds

### 2. Logging and Auditing

#### CloudTrail Integration
Enable CloudTrail for KMS events:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "kms:*"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:RequestTag/Logging": "enabled"
        }
      }
    }
  ]
}
```

#### Custom Logging
Implement custom logging for sensitive operations:

```python
import logging
import json

def log_kms_operation(operation, key_id, success, error=None):
    log_entry = {
        'timestamp': time.time(),
        'operation': operation,
        'key_id': key_id,
        'success': success,
        'error': str(error) if error else None,
        'user_agent': 'custom-kms-client'
    }
    
    logging.info(json.dumps(log_entry))
```

## 🏗️ Operational Best Practices

### 1. Environment Management

#### Environment Separation
- **Different keys per environment**: Never share keys between dev/staging/prod
- **Environment-specific policies**: Tailor IAM policies to environment needs
- **Tagging strategy**: Use consistent tagging across environments

#### Configuration Management
- **Use Terraform/CloudFormation**: Infrastructure as code for key management
- **Version control**: Keep key configurations in version control
- **Environment variables**: Use environment variables for sensitive configuration

### 2. Backup and Recovery

#### Key Backup
- **Export key material**: For customer-managed keys when needed
- **Backup policies**: Store key policies and configurations
- **Recovery procedures**: Document key recovery procedures

#### Disaster Recovery
- **Multi-region keys**: Have keys in multiple regions
- **Cross-region replication**: For critical data
- **Recovery testing**: Regularly test recovery procedures

### 3. Compliance and Governance

#### Compliance Frameworks
- **SOX compliance**: Implement controls for financial data
- **HIPAA compliance**: For healthcare data
- **GDPR compliance**: For personal data
- **PCI DSS**: For payment card data

#### Audit Procedures
- **Regular audits**: Conduct regular security audits
- **Access reviews**: Review key access regularly
- **Policy reviews**: Update policies based on audit findings

## 🚨 Security Checklist

### Before Production
- [ ] IAM policies follow least privilege principle
- [ ] Key rotation is enabled
- [ ] Monitoring and alerting are configured
- [ ] Encryption context is used appropriately
- [ ] Error handling and retry logic are implemented
- [ ] Logging and auditing are enabled
- [ ] Backup and recovery procedures are documented
- [ ] Compliance requirements are met

### Ongoing Operations
- [ ] Monitor key usage patterns
- [ ] Review access logs regularly
- [ ] Update policies as needed
- [ ] Test disaster recovery procedures
- [ ] Conduct security assessments
- [ ] Update documentation
- [ ] Train team members on best practices

## 📚 Additional Resources

- [AWS KMS Developer Guide](https://docs.aws.amazon.com/kms/)
- [AWS KMS API Reference](https://docs.aws.amazon.com/kms/latest/APIReference/)
- [AWS Security Best Practices](https://aws.amazon.com/security/security-learning/)
- [AWS Well-Architected Framework](https://aws.amazon.com/architecture/well-architected/) 