#!/usr/bin/env python3
"""
Enhanced Envelope Encryption with AWS KMS
Supports file encryption, compression, and robust error handling
"""

import boto3
import base64
import json
import gzip
import os
import sys
import argparse
from pathlib import Path
from typing import Dict, Tuple, Optional
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class KMSEnvelopeEncryption:
    """Enhanced envelope encryption using AWS KMS"""
    
    def __init__(self, key_id: str, region: Optional[str] = None):
        """Initialize KMS client and key ID"""
        self.key_id = key_id
        self.kms = boto3.client('kms', region_name=region)
        
    def generate_data_key(self, key_spec: str = 'AES_256') -> Tuple[bytes, bytes]:
        """Generate a data encryption key using KMS"""
        try:
            response = self.kms.generate_data_key(
                KeyId=self.key_id,
                KeySpec=key_spec
            )
            return response['Plaintext'], response['CiphertextBlob']
        except Exception as e:
            logger.error(f"Failed to generate data key: {e}")
            raise
    
    def encrypt_data(self, data: bytes, compress: bool = True) -> Dict:
        """Encrypt data using envelope encryption"""
        try:
            # Compress data if requested
            if compress:
                data = gzip.compress(data)
                logger.info("Data compressed")
            
            # Generate data encryption key
            plaintext_key, ciphertext_key = self.generate_data_key()
            
            # Generate random nonce
            nonce = get_random_bytes(12)
            
            # Encrypt data with AES-GCM
            cipher = AES.new(plaintext_key, AES.MODE_GCM, nonce=nonce)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            
            # Create encrypted package
            encrypted_package = {
                'version': '1.0',
                'algorithm': 'AES-GCM',
                'compressed': compress,
                'nonce': base64.b64encode(nonce).decode('utf-8'),
                'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
                'tag': base64.b64encode(tag).decode('utf-8'),
                'encrypted_key': base64.b64encode(ciphertext_key).decode('utf-8')
            }
            
            logger.info(f"Data encrypted successfully (size: {len(data)} bytes)")
            return encrypted_package
            
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise
    
    def decrypt_data(self, encrypted_package: Dict) -> bytes:
        """Decrypt data using envelope encryption"""
        try:
            # Decrypt the data encryption key
            encrypted_key = base64.b64decode(encrypted_package['encrypted_key'])
            decrypted_key = self.kms.decrypt(CiphertextBlob=encrypted_key)['Plaintext']
            
            # Decode components
            nonce = base64.b64decode(encrypted_package['nonce'])
            ciphertext = base64.b64decode(encrypted_package['ciphertext'])
            tag = base64.b64decode(encrypted_package['tag'])
            
            # Decrypt data
            cipher = AES.new(decrypted_key, AES.MODE_GCM, nonce=nonce)
            decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
            
            # Decompress if needed
            if encrypted_package.get('compressed', False):
                decrypted_data = gzip.decompress(decrypted_data)
                logger.info("Data decompressed")
            
            logger.info(f"Data decrypted successfully (size: {len(decrypted_data)} bytes)")
            return decrypted_data
            
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise
    
    def encrypt_file(self, input_path: str, output_path: str, compress: bool = True) -> None:
        """Encrypt a file using envelope encryption"""
        try:
            input_file = Path(input_path)
            if not input_file.exists():
                raise FileNotFoundError(f"Input file not found: {input_path}")
            
            # Read input file
            with open(input_file, 'rb') as f:
                data = f.read()
            
            logger.info(f"Reading file: {input_path} ({len(data)} bytes)")
            
            # Encrypt data
            encrypted_package = self.encrypt_data(data, compress)
            
            # Write encrypted package
            output_file = Path(output_path)
            with open(output_file, 'w') as f:
                json.dump(encrypted_package, f, indent=2)
            
            logger.info(f"Encrypted file saved to: {output_path}")
            
        except Exception as e:
            logger.error(f"File encryption failed: {e}")
            raise
    
    def decrypt_file(self, input_path: str, output_path: str) -> None:
        """Decrypt a file using envelope encryption"""
        try:
            input_file = Path(input_path)
            if not input_file.exists():
                raise FileNotFoundError(f"Input file not found: {input_path}")
            
            # Read encrypted package
            with open(input_file, 'r') as f:
                encrypted_package = json.load(f)
            
            logger.info(f"Reading encrypted file: {input_path}")
            
            # Decrypt data
            decrypted_data = self.decrypt_data(encrypted_package)
            
            # Write decrypted file
            output_file = Path(output_path)
            with open(output_file, 'wb') as f:
                f.write(decrypted_data)
            
            logger.info(f"Decrypted file saved to: {output_path}")
            
        except Exception as e:
            logger.error(f"File decryption failed: {e}")
            raise

def main():
    """Main function for CLI usage"""
    parser = argparse.ArgumentParser(description='AWS KMS Envelope Encryption Tool')
    parser.add_argument('--key-id', default='alias/my-app-key', help='KMS Key ID or Alias')
    parser.add_argument('--region', help='AWS Region')
    parser.add_argument('--action', choices=['encrypt', 'decrypt'], required=True, help='Action to perform')
    parser.add_argument('--input', required=True, help='Input file or string')
    parser.add_argument('--output', help='Output file (required for file operations)')
    parser.add_argument('--no-compress', action='store_true', help='Disable compression')
    parser.add_argument('--string', action='store_true', help='Treat input as string instead of file')
    
    args = parser.parse_args()
    
    try:
        # Initialize encryption handler
        kms_encryption = KMSEnvelopeEncryption(args.key_id, args.region)
        
        if args.string:
            # String encryption/decryption
            if args.action == 'encrypt':
                data = args.input.encode('utf-8')
                encrypted = kms_encryption.encrypt_data(data, not args.no_compress)
                print(json.dumps(encrypted, indent=2))
            else:  # decrypt
                encrypted_package = json.loads(args.input)
                decrypted = kms_encryption.decrypt_data(encrypted_package)
                print(decrypted.decode('utf-8'))
        else:
            # File encryption/decryption
            if not args.output:
                print("Error: --output is required for file operations")
                sys.exit(1)
            
            if args.action == 'encrypt':
                kms_encryption.encrypt_file(args.input, args.output, not args.no_compress)
            else:  # decrypt
                kms_encryption.decrypt_file(args.input, args.output)
                
    except Exception as e:
        logger.error(f"Operation failed: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
