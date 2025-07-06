import boto3, json, os

kms = boto3.client("kms")
admin_arn = os.getenv("ADMIN_ARN", "arn:aws:iam::123456789012:user/dev-admin")

policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowAdmin",
            "Effect": "Allow",
            "Principal": {"AWS": admin_arn},
            "Action": "kms:*",
            "Resource": "*"
        }
    ]
}

key = kms.create_key(
    Description="KMS key created via Python",
    KeyUsage="ENCRYPT_DECRYPT",
    Origin="AWS_KMS",
    Policy=json.dumps(policy)
)

kms.create_alias(
    AliasName=os.getenv("KMS_ALIAS", "alias/my-app-key"),
    TargetKeyId=key["KeyMetadata"]["KeyId"]
)

print("Created KMS Key:", key["KeyMetadata"]["KeyId"])
