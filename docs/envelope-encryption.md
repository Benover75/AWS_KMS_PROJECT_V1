# Envelope Encryption

Envelope encryption uses a data key (DEK) to encrypt large data.
The DEK is encrypted with a KMS key.

## Steps
1. Generate DEK using KMS.
2. Encrypt data with DEK locally.
3. Store encrypted DEK and ciphertext.
4. Decrypt DEK with KMS.
5. Decrypt data with DEK locally.

## Benefits
- Efficient for large data
- Minimal KMS API calls
- Seamless key rotation
