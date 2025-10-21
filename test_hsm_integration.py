"""
Tests for HSM (Hardware Security Module) Integration
"""

import os
import unittest
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch, MagicMock

from hsm_integration import (
    HSMType,
    HSMFactory,
    HSMKey,
    HSMError,
    HSMUnavailableError,
    HSMOperationError,
)

class TestFileBasedHSM(unittest.TestCase):
    """Test the file-based HSM implementation"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_dir = Path(tempfile.mkdtemp(prefix="test_hsm_"))
        self.config = {
            'keys_dir': str(self.test_dir / 'hsm_keys'),
            'hsm_type': 'file'
        }
        
    def tearDown(self):
        """Clean up test environment"""
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir)
    
    def test_create_session(self):
        """Test creating a file-based HSM session"""
        hsm = HSMFactory.create_session(HSMType.FILE_BASED, self.config)
        self.assertIsNotNone(hsm)
        self.assertTrue(hsm.is_available())
        hsm.close()
    
    def test_generate_key(self):
        """Test generating a key in the file-based HSM"""
        hsm = HSMFactory.create_session(HSMType.FILE_BASED, self.config)
        
        # Generate a key
        key = hsm.generate_key('test_key', 'AES-256')
        
        # Verify key properties
        self.assertEqual(key.key_id, 'test_key')
        self.assertEqual(key.key_type, 'AES-256')
        self.assertEqual(key.attributes['key_size'], 256)
        self.assertFalse(key.attributes['extractable'])
        
        # Verify key was saved to disk
        key_file = Path(self.config['keys_dir']) / 'test_key.json'
        self.assertTrue(key_file.exists())
        
        # Clean up
        hsm.close()
    
    def test_duplicate_key(self):
        """Test that duplicate keys are not allowed"""
        hsm = HSMFactory.create_session(HSMType.FILE_BASED, self.config)
        
        # Create first key (should succeed)
        hsm.generate_key('duplicate_test', 'AES-256')
        
        # Try to create duplicate key (should fail)
        with self.assertRaises(HSMOperationError):
            hsm.generate_key('duplicate_test', 'AES-256')
        
        hsm.close()
    
    def test_key_persistence(self):
        """Test that keys are persisted between sessions"""
        # Create first session and generate a key
        hsm1 = HSMFactory.create_session(HSMType.FILE_BASED, self.config)
        hsm1.generate_key('persistent_key', 'AES-256')
        hsm1.close()
        
        # Create a new session and verify the key exists
        hsm2 = HSMFactory.create_session(HSMType.FILE_BASED, self.config)
        key = hsm2.get_key('persistent_key')
        
        self.assertIsNotNone(key)
        self.assertEqual(key.key_id, 'persistent_key')
        hsm2.close()

@unittest.skipUnless(os.getenv('PKCS11_TESTS'), 'PKCS#11 tests require HSM hardware')
class TestPKCS11HSM(unittest.TestCase):
    """Test the PKCS#11 HSM implementation (requires actual HSM hardware)"""
    
    def setUp(self):
        """Set up test environment"""
        self.config = {
            'pkcs11_library': os.getenv('PKCS11_LIBRARY'),
            'slot': int(os.getenv('PKCS11_SLOT', '0')),
            'pin': os.getenv('PKCS11_PIN', '1234')
        }
    
    def test_create_session(self):
        """Test creating a PKCS#11 HSM session"""
        try:
            hsm = HSMFactory.create_session(HSMType.PKCS11, self.config)
            self.assertIsNotNone(hsm)
            self.assertTrue(hsm.is_available())
            hsm.close()
        except HSMUnavailableError as e:
            self.skipTest(f"PKCS#11 HSM not available: {e}")
    
    def test_generate_key(self):
        """Test generating a key in the PKCS#11 HSM"""
        try:
            hsm = HSMFactory.create_session(HSMType.PKCS11, self.config)
            
            # Generate a key
            key = hsm.generate_key('test_pkcs11_key', 'AES-256')
            
            # Verify key properties
            self.assertEqual(key.key_id, 'test_pkcs11_key')
            self.assertEqual(key.attributes['key_size'], 256)
            
            # Clean up
            hsm.delete_key('test_pkcs11_key')
            hsm.close()
            
        except HSMUnavailableError as e:
            self.skipTest(f"PKCS#11 HSM not available: {e}")

class TestHSMFactory(unittest.TestCase):
    """Test the HSM factory"""
    
    def test_create_unsupported_type(self):
        """Test creating an unsupported HSM type"""
        with self.assertRaises(ValueError):
            HSMFactory.create_session('UNSUPPORTED_TYPE', {})

class TestHSMKey(unittest.TestCase):
    """Test the HSMKey class"""
    
    def test_hsm_key_creation(self):
        """Test creating an HSMKey instance"""
        key = HSMKey(
            key_id='test_key',
            key_type='AES-256',
            public_data=b'test_public_data',
            attributes={'key_size': 256, 'extractable': False}
        )
        
        self.assertEqual(key.key_id, 'test_key')
        self.assertEqual(key.key_type, 'AES-256')
        self.assertEqual(key.public_data, b'test_public_data')
        self.assertEqual(key.attributes['key_size'], 256)
        self.assertFalse(key.attributes['extractable'])

if __name__ == '__main__':
    unittest.main()
