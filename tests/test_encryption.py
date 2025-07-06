#!/usr/bin/env python3
"""
Test suite for KMS Envelope Encryption
"""

import unittest
import tempfile
import os
import json
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from scripts.envelope_encryption import KMSEnvelopeEncryption
import boto3
from unittest.mock import Mock, patch, MagicMock

class TestKMSEnvelopeEncryption(unittest.TestCase):
    """Test cases for KMS Envelope Encryption"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.test_key_id = "alias/test-key"
        self.test_data = b"Hello, this is test data for encryption!"
        self.test_file_content = b"This is test file content for encryption testing."
        
        # Create temporary files
        self.temp_dir = tempfile.mkdtemp()
        self.test_file_path = os.path.join(self.temp_dir, "test_file.txt")
        self.encrypted_file_path = os.path.join(self.temp_dir, "test_file.encrypted")
        self.decrypted_file_path = os.path.join(self.temp_dir, "test_file_decrypted.txt")
        
        # Write test file
        with open(self.test_file_path, 'wb') as f:
            f.write(self.test_file_content)
    
    def tearDown(self):
        """Clean up test fixtures"""
        # Remove temporary files
        for file_path in [self.test_file_path, self.encrypted_file_path, self.decrypted_file_path]:
            if os.path.exists(file_path):
                os.remove(file_path)
        
        # Remove temporary directory
        if os.path.exists(self.temp_dir):
            os.rmdir(self.temp_dir)
    
    @patch('boto3.client')
    def test_initialization(self, mock_boto3_client):
        """Test KMS client initialization"""
        mock_kms = Mock()
        mock_boto3_client.return_value = mock_kms
        
        encryption = KMSEnvelopeEncryption(self.test_key_id, "us-east-1")
        
        self.assertEqual(encryption.key_id, self.test_key_id)
        mock_boto3_client.assert_called_once_with('kms', region_name="us-east-1")
    
    @patch('boto3.client')
    def test_generate_data_key(self, mock_boto3_client):
        """Test data key generation"""
        mock_kms = Mock()
        mock_response = {
            'Plaintext': b'test_plaintext_key_32_bytes_long',
            'CiphertextBlob': b'encrypted_key_blob'
        }
        mock_kms.generate_data_key.return_value = mock_response
        mock_boto3_client.return_value = mock_kms
        
        encryption = KMSEnvelopeEncryption(self.test_key_id)
        plaintext_key, ciphertext_key = encryption.generate_data_key()
        
        self.assertEqual(plaintext_key, mock_response['Plaintext'])
        self.assertEqual(ciphertext_key, mock_response['CiphertextBlob'])
        mock_kms.generate_data_key.assert_called_once_with(
            KeyId=self.test_key_id,
            KeySpec='AES_256'
        )
    
    @patch('boto3.client')
    def test_encrypt_data(self, mock_boto3_client):
        """Test data encryption"""
        mock_kms = Mock()
        mock_response = {
            'Plaintext': b'test_plaintext_key_32_bytes_long',
            'CiphertextBlob': b'encrypted_key_blob'
        }
        mock_kms.generate_data_key.return_value = mock_response
        mock_boto3_client.return_value = mock_kms
        
        encryption = KMSEnvelopeEncryption(self.test_key_id)
        encrypted_package = encryption.encrypt_data(self.test_data)
        
        # Verify package structure
        self.assertIn('version', encrypted_package)
        self.assertIn('algorithm', encrypted_package)
        self.assertIn('compressed', encrypted_package)
        self.assertIn('nonce', encrypted_package)
        self.assertIn('ciphertext', encrypted_package)
        self.assertIn('tag', encrypted_package)
        self.assertIn('encrypted_key', encrypted_package)
        
        # Verify values
        self.assertEqual(encrypted_package['version'], '1.0')
        self.assertEqual(encrypted_package['algorithm'], 'AES-GCM')
        self.assertTrue(encrypted_package['compressed'])
    
    @patch('boto3.client')
    def test_decrypt_data(self, mock_boto3_client):
        """Test data decryption"""
        mock_kms = Mock()
        mock_response = {
            'Plaintext': b'test_plaintext_key_32_bytes_long',
            'CiphertextBlob': b'encrypted_key_blob'
        }
        mock_kms.generate_data_key.return_value = mock_response
        mock_kms.decrypt.return_value = {'Plaintext': b'test_plaintext_key_32_bytes_long'}
        mock_boto3_client.return_value = mock_kms
        
        encryption = KMSEnvelopeEncryption(self.test_key_id)
        
        # First encrypt
        encrypted_package = encryption.encrypt_data(self.test_data)
        
        # Then decrypt
        decrypted_data = encryption.decrypt_data(encrypted_package)
        
        # Verify decryption
        self.assertEqual(decrypted_data, self.test_data)
    
    @patch('boto3.client')
    def test_encrypt_file(self, mock_boto3_client):
        """Test file encryption"""
        mock_kms = Mock()
        mock_response = {
            'Plaintext': b'test_plaintext_key_32_bytes_long',
            'CiphertextBlob': b'encrypted_key_blob'
        }
        mock_kms.generate_data_key.return_value = mock_response
        mock_boto3_client.return_value = mock_kms
        
        encryption = KMSEnvelopeEncryption(self.test_key_id)
        encryption.encrypt_file(self.test_file_path, self.encrypted_file_path)
        
        # Verify encrypted file was created
        self.assertTrue(os.path.exists(self.encrypted_file_path))
        
        # Verify file contains valid JSON
        with open(self.encrypted_file_path, 'r') as f:
            encrypted_package = json.load(f)
        
        self.assertIn('version', encrypted_package)
        self.assertIn('ciphertext', encrypted_package)
    
    @patch('boto3.client')
    def test_decrypt_file(self, mock_boto3_client):
        """Test file decryption"""
        mock_kms = Mock()
        mock_response = {
            'Plaintext': b'test_plaintext_key_32_bytes_long',
            'CiphertextBlob': b'encrypted_key_blob'
        }
        mock_kms.generate_data_key.return_value = mock_response
        mock_kms.decrypt.return_value = {'Plaintext': b'test_plaintext_key_32_bytes_long'}
        mock_boto3_client.return_value = mock_kms
        
        encryption = KMSEnvelopeEncryption(self.test_key_id)
        
        # First encrypt file
        encryption.encrypt_file(self.test_file_path, self.encrypted_file_path)
        
        # Then decrypt file
        encryption.decrypt_file(self.encrypted_file_path, self.decrypted_file_path)
        
        # Verify decrypted file was created
        self.assertTrue(os.path.exists(self.decrypted_file_path))
        
        # Verify content matches
        with open(self.decrypted_file_path, 'rb') as f:
            decrypted_content = f.read()
        
        self.assertEqual(decrypted_content, self.test_file_content)
    
    def test_encrypt_data_no_compression(self):
        """Test data encryption without compression"""
        with patch('boto3.client') as mock_boto3_client:
            mock_kms = Mock()
            mock_response = {
                'Plaintext': b'test_plaintext_key_32_bytes_long',
                'CiphertextBlob': b'encrypted_key_blob'
            }
            mock_kms.generate_data_key.return_value = mock_response
            mock_boto3_client.return_value = mock_kms
            
            encryption = KMSEnvelopeEncryption(self.test_key_id)
            encrypted_package = encryption.encrypt_data(self.test_data, compress=False)
            
            self.assertFalse(encrypted_package['compressed'])
    
    def test_error_handling_invalid_file(self):
        """Test error handling for invalid file"""
        encryption = KMSEnvelopeEncryption(self.test_key_id)
        
        with self.assertRaises(FileNotFoundError):
            encryption.encrypt_file("nonexistent_file.txt", "output.txt")
    
    def test_error_handling_kms_failure(self):
        """Test error handling for KMS failures"""
        with patch('boto3.client') as mock_boto3_client:
            mock_kms = Mock()
            mock_kms.generate_data_key.side_effect = Exception("KMS Error")
            mock_boto3_client.return_value = mock_kms
            
            encryption = KMSEnvelopeEncryption(self.test_key_id)
            
            with self.assertRaises(Exception):
                encryption.encrypt_data(self.test_data)

class TestSecurityValidation(unittest.TestCase):
    """Test cases for security validation"""
    
    def test_key_size_validation(self):
        """Test that generated keys are the correct size"""
        with patch('boto3.client') as mock_boto3_client:
            mock_kms = Mock()
            # Simulate AES-256 key (32 bytes)
            mock_response = {
                'Plaintext': b'x' * 32,
                'CiphertextBlob': b'encrypted_key_blob'
            }
            mock_kms.generate_data_key.return_value = mock_response
            mock_boto3_client.return_value = mock_kms
            
            encryption = KMSEnvelopeEncryption("alias/test-key")
            plaintext_key, _ = encryption.generate_data_key()
            
            # Verify key size is 32 bytes (256 bits)
            self.assertEqual(len(plaintext_key), 32)
    
    def test_nonce_uniqueness(self):
        """Test that nonces are unique for each encryption"""
        with patch('boto3.client') as mock_boto3_client:
            mock_kms = Mock()
            mock_response = {
                'Plaintext': b'x' * 32,
                'CiphertextBlob': b'encrypted_key_blob'
            }
            mock_kms.generate_data_key.return_value = mock_response
            mock_boto3_client.return_value = mock_kms
            
            encryption = KMSEnvelopeEncryption("alias/test-key")
            
            # Encrypt same data twice
            encrypted1 = encryption.encrypt_data(b"test data")
            encrypted2 = encryption.encrypt_data(b"test data")
            
            # Verify nonces are different
            nonce1 = encrypted1['nonce']
            nonce2 = encrypted2['nonce']
            self.assertNotEqual(nonce1, nonce2)
    
    def test_ciphertext_uniqueness(self):
        """Test that ciphertexts are unique for each encryption"""
        with patch('boto3.client') as mock_boto3_client:
            mock_kms = Mock()
            mock_response = {
                'Plaintext': b'x' * 32,
                'CiphertextBlob': b'encrypted_key_blob'
            }
            mock_kms.generate_data_key.return_value = mock_response
            mock_boto3_client.return_value = mock_kms
            
            encryption = KMSEnvelopeEncryption("alias/test-key")
            
            # Encrypt same data twice
            encrypted1 = encryption.encrypt_data(b"test data")
            encrypted2 = encryption.encrypt_data(b"test data")
            
            # Verify ciphertexts are different
            ciphertext1 = encrypted1['ciphertext']
            ciphertext2 = encrypted2['ciphertext']
            self.assertNotEqual(ciphertext1, ciphertext2)

if __name__ == '__main__':
    unittest.main() 