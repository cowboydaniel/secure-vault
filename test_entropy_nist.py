"""
Test module for NIST SP 800-22 statistical tests on entropy sources.
"""

import unittest
from test_nist_sp800_22 import test_nist_suite
from entropy_monitor import EntropySource, EntropyMonitor
from crypto_utils import secure_random_bytes


class TestEntropyNIST(unittest.TestCase):
    """Test NIST SP 800-22 statistical tests on entropy sources."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.monitor = EntropyMonitor(sample_interval=0.1, window_size=10)
        
        # Generate test data from different sources
        self.test_data = {
            'urandom': secure_random_bytes(1024 * 8),  # 8KB from OS RNG
            'zeros': bytes([0] * 1024),       # All zeros (should fail tests)
            'ones': bytes([255] * 1024),      # All ones (should fail tests)
            'alternating': bytes([i % 2 * 255 for i in range(1024)]),  # 0101...
        }
    
    def test_nist_on_urandom(self):
        """Test NIST SP 800-22 on OS urandom output."""
        data = self.test_data['urandom']
        results = test_nist_suite(data)
        
        # Check that all tests passed
        for test_name, result in results.items():
            with self.subTest(test=test_name):
                self.assertTrue(result['passed'], 
                              f"{result['description']} failed (p-value: {result['p_value']:.6f})")
    
    def test_nist_on_zeros(self):
        """Test that all-zeros data fails NIST tests."""
        data = self.test_data['zeros']
        results = test_nist_suite(data)
        
        # Check that at least one test failed
        passed_tests = [r['passed'] for r in results.values() if 'passed' in r]
        self.assertFalse(all(passed_tests), 
                        "All NIST tests passed on all-zeros data (should fail)")
    
    def test_nist_on_ones(self):
        """Test that all-ones data fails NIST tests."""
        data = self.test_data['ones']
        results = test_nist_suite(data)
        
        # Check that at least one test failed
        passed_tests = [r['passed'] for r in results.values() if 'passed' in r]
        self.assertFalse(all(passed_tests), 
                        "All NIST tests passed on all-ones data (should fail)")
    
    def test_nist_on_alternating(self):
        """Test that alternating pattern data fails NIST tests."""
        data = self.test_data['alternating']
        results = test_nist_suite(data)
        
        # Check that at least one test failed
        passed_tests = [r['passed'] for r in results.values() if 'passed' in r]
        self.assertFalse(all(passed_tests), 
                        "All NIST tests passed on alternating pattern data (should fail)")
    
    def test_nist_on_entropy_monitor_samples(self):
        """Test NIST SP 800-22 on samples from EntropyMonitor."""
        # Collect samples from all sources
        samples = []
        for source in EntropySource:
            try:
                sample = self.monitor.collect_sample(source, secure_random_bytes(1024))
                samples.append((source.name, sample.data))
            except Exception as e:
                print(f"Warning: Could not collect sample from {source.name}: {e}")
        
        # Test each sample
        for source_name, data in samples:
            with self.subTest(source=source_name):
                results = test_nist_suite(data)
                
                # Check that all tests passed
                for test_name, result in results.items():
                    with self.subTest(test=test_name):
                        self.assertTrue(result.get('passed', False), 
                                      f"{result.get('description', test_name)} failed for {source_name} "
                                      f"(p-value: {result.get('p_value', 'N/A'):.6f})")


if __name__ == "__main__":
    unittest.main()
