#!/bin/bash

set -e

KEY_OUTPUT=$(aws kms create-key \
  --description "My CLI KMS key" \
  --policy file://../config/dev/kms-policy.json)

KEY_ID=$(echo $KEY_OUTPUT | jq -r .KeyMetadata.KeyId)

aws kms create-alias \
  --alias-name alias/my-app-key \
  --target-key-id $KEY_ID

echo "Created KMS key with ID: $KEY_ID"
