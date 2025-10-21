"""
Tests for entropy monitoring system.
"""

import unittest
import time
import numpy as np
from unittest.mock import patch, MagicMock
from entropy_monitor import (
    EntropyMonitor, EntropySource, EntropyHealthStatus, EntropyMetrics,
    entropy_monitor, start_monitoring, stop_monitoring
)

class TestEntropyMonitor(unittest.TestCase):
    """Test cases for the EntropyMonitor class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.monitor = EntropyMonitor(sample_interval=0.1, window_size=10)
        
    def tearDown(self):
        """Clean up after tests."""
        self.monitor.stop()
        
    def test_initial_state(self):
        """Test initial state of the monitor."""
        self.assertFalse(self.monitor.running)
        self.assertIsNone(self.monitor.monitor_thread)
        
    def test_start_stop(self):
        """Test starting and stopping the monitor."""
        self.monitor.start()
        self.assertTrue(self.monitor.running)
        self.assertIsNotNone(self.monitor.monitor_thread)
        
        self.monitor.stop()
        self.assertFalse(self.monitor.running)
        
    @patch('entropy_monitor.EntropyMonitor._collect_os_urandom')
    @patch('entropy_monitor.EntropyMonitor._collect_system_random')
    @patch('entropy_monitor.EntropyMonitor._collect_timing_entropy')
    def test_collect_sample(self, mock_timing, mock_sysrand, mock_urandom):
        """Test collecting and analyzing a sample."""
        # Mock the collection methods
        mock_urandom.return_value = bytes([i % 256 for i in range(1024)])
        mock_sysrand.return_value = bytes([(i + 1) % 256 for i in range(1024)])
        mock_timing.return_value = bytes([(i + 2) % 256 for i in range(1000)])
        
        # Collect samples
        sample1 = self.monitor.collect_sample(EntropySource.OS_URANDOM, mock_urandom.return_value)
        sample2 = self.monitor.collect_sample(EntropySource.SYSTEM_RANDOM, mock_sysrand.return_value)
        sample3 = self.monitor.collect_sample(EntropySource.TIMING, mock_timing.return_value)
        
        # Verify samples were collected
        self.assertEqual(sample1.source, EntropySource.OS_URANDOM)
        self.assertEqual(sample2.source, EntropySource.SYSTEM_RANDOM)
        self.assertEqual(sample3.source, EntropySource.TIMING)
        
        # Verify metrics were calculated
        self.assertGreater(sample1.metrics.min_entropy, 0)
        self.assertGreater(sample1.metrics.shannon_entropy, 0)
        
    def test_metrics_calculation(self):
        """Test entropy metrics calculation."""
        # Test with known input
        test_data = bytes([i % 256 for i in range(1000)])
        metrics = self.monitor._calculate_metrics(test_data)
        
        # Verify metrics are within expected ranges
        self.assertGreaterEqual(metrics.min_entropy, 0)
        self.assertLessEqual(metrics.min_entropy, 8)  # 8 bits per byte max
        
        self.assertGreaterEqual(metrics.shannon_entropy, 0)
        self.assertLessEqual(metrics.shannon_entropy, 8)
        
        self.assertGreater(metrics.chi_square, 0)
        self.assertGreater(metrics.runs_test, 0)
        
    def test_health_assessment(self):
        """Test health assessment of entropy sources."""
        # Test with good data
        good_metrics = EntropyMetrics(
            min_entropy=7.5,
            shannon_entropy=7.9,
            chi_square=256.0,  # p-value ~0.5 for 255 degrees of freedom
            runs_test=0.5
        )
        
        # Test with bad data (low entropy)
        bad_metrics = EntropyMetrics(
            min_entropy=0.1,
            shannon_entropy=0.5,
            chi_square=1000.0,  # Very low p-value
            runs_test=0.001
        )
        
        # Create test samples
        good_sample = EntropySample(
            source=EntropySource.OS_URANDOM,
            data=bytes([i % 256 for i in range(1000)]),
            metrics=good_metrics
        )
        
        bad_sample = EntropySample(
            source=EntropySource.OS_URANDOM,
            data=bytes([0] * 1000),  # All zeros - very bad entropy
            metrics=bad_metrics
        )
        
        # Add samples to monitor
        with self.monitor.lock:
            self.monitor.samples[EntropySource.OS_URANDOM].append(good_sample)
            
        # Check health
        health = self.monitor.assess_health(EntropySource.OS_URANDOM)
        self.assertEqual(health, EntropyHealthStatus.HEALTHY)
        
        # Add bad sample and check health
        with self.monitor.lock:
            self.monitor.samples[EntropySource.OS_URANDOM].append(bad_sample)
            
        health = self.monitor.assess_health(EntropySource.OS_URANDOM)
        self.assertNotEqual(health, EntropyHealthStatus.HEALTHY)
        
    def test_health_callbacks(self):
        """Test health status change callbacks."""
        callback_mock = MagicMock()
        self.monitor.add_health_callback(callback_mock)
        
        # Simulate health change
        self.monitor._notify_health_change(
            EntropySource.OS_URANDOM,
            EntropyHealthStatus.DEGRADED
        )
        
        # Verify callback was called
        callback_mock.assert_called_once_with(
            EntropySource.OS_URANDOM,
            EntropyHealthStatus.DEGRADED
        )
        
    def test_global_monitor(self):
        """Test the global monitor instance."""
        try:
            start_monitoring()
            self.assertTrue(entropy_monitor.running)
            
            # Give it a moment to collect some samples
            time.sleep(0.5)
            
            # Check that we have some metrics
            metrics = get_entropy_metrics(EntropySource.OS_URANDOM)
            self.assertIsNotNone(metrics)
            
            # Check health status
            health = get_health_status(EntropySource.OS_URANDOM)
            self.assertIn(health, list(EntropyHealthStatus))
            
        finally:
            stop_monitoring()
            self.assertFalse(entropy_monitor.running)

if __name__ == '__main__':
    unittest.main()
