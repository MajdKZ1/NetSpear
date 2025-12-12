"""
Unit tests for utility functions.
"""
import unittest
from unittest.mock import patch, MagicMock
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils import validate_ip, validate_port, validate_url, validate_file_path, check_privileges


class TestUtils(unittest.TestCase):
    """Test cases for utility functions."""
    
    def test_validate_ip_valid(self):
        """Test valid IP addresses."""
        with patch('builtins.input', return_value='y'):
            self.assertTrue(validate_ip("192.168.1.1"))
            self.assertTrue(validate_ip("8.8.8.8"))
            self.assertTrue(validate_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334"))  # IPv6
    
    def test_validate_ip_invalid(self):
        """Test invalid IP addresses."""
        self.assertFalse(validate_ip("256.256.256.256"))
        self.assertFalse(validate_ip("not.an.ip"))
        self.assertFalse(validate_ip(""))
    
    def test_validate_port_valid(self):
        """Test valid port numbers."""
        self.assertTrue(validate_port(80))
        self.assertTrue(validate_port(443))
        self.assertTrue(validate_port(65535))
        self.assertTrue(validate_port("8080"))
    
    def test_validate_port_invalid(self):
        """Test invalid port numbers."""
        self.assertFalse(validate_port(0))
        self.assertFalse(validate_port(65536))
        self.assertFalse(validate_port(-1))
        self.assertFalse(validate_port("invalid"))
    
    def test_validate_url_valid(self):
        """Test valid URLs."""
        self.assertTrue(validate_url("https://example.com"))
        self.assertTrue(validate_url("http://example.com/path"))
        self.assertTrue(validate_url("example.com"))  # Should add http://
    
    def test_validate_url_invalid(self):
        """Test invalid URLs."""
        self.assertFalse(validate_url("not a url"))
        self.assertFalse(validate_url(""))
    
    @patch('pathlib.Path.exists')
    def test_validate_file_path(self, mock_exists):
        """Test file path validation."""
        mock_exists.return_value = True
        self.assertTrue(validate_file_path("/path/to/file", must_exist=True))
        
        mock_exists.return_value = False
        self.assertFalse(validate_file_path("/nonexistent", must_exist=True))
        self.assertTrue(validate_file_path("/nonexistent", must_exist=False))
    
    @patch('os.geteuid')
    def test_check_privileges_root(self, mock_geteuid):
        """Test privilege check as root."""
        mock_geteuid.return_value = 0
        self.assertTrue(check_privileges())
    
    @patch('os.geteuid')
    def test_check_privileges_non_root(self, mock_geteuid):
        """Test privilege check as non-root."""
        mock_geteuid.return_value = 1000
        self.assertFalse(check_privileges())


if __name__ == '__main__':
    unittest.main()


