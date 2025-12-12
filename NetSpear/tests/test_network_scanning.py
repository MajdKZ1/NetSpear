"""
Unit tests for network scanning module.
"""
import unittest
from unittest.mock import Mock, patch, MagicMock
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from network_scanning import NetworkScanner
from utils import validate_ip


class TestNetworkScanner(unittest.TestCase):
    """Test cases for NetworkScanner class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.scanner = NetworkScanner()
    
    def test_init(self):
        """Test NetworkScanner initialization."""
        self.assertIsInstance(self.scanner.scan_results, dict)
        self.assertEqual(len(self.scanner.scan_results), 0)
    
    @patch('network_scanning.validate_ip')
    def test_run_nmap_scan_invalid_ip(self, mock_validate):
        """Test scan with invalid IP address."""
        mock_validate.return_value = False
        result, vulns = self.scanner.run_nmap_scan("invalid", "quick")
        self.assertEqual(result, {})
        self.assertEqual(vulns, [])
    
    def test_requires_root_args(self):
        """Test root requirement detection."""
        self.assertTrue(self.scanner._requires_root_args("-sS"))
        self.assertTrue(self.scanner._requires_root_args("-A"))
        self.assertFalse(self.scanner._requires_root_args("-sT"))
    
    def test_tool_exists(self):
        """Test tool existence checking."""
        with patch('shutil.which') as mock_which:
            mock_which.return_value = "/usr/bin/nmap"
            self.assertTrue(self.scanner._tool_exists("nmap"))
            
            mock_which.return_value = None
            self.assertFalse(self.scanner._tool_exists("nonexistent"))


if __name__ == '__main__':
    unittest.main()


