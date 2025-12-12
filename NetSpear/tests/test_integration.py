"""
Integration tests for major NetSpear workflows.
"""
import unittest
from unittest.mock import Mock, patch, MagicMock
import sys
from pathlib import Path
import tempfile
import shutil

sys.path.insert(0, str(Path(__file__).parent.parent))

from main import NetSpearNetworkAnalyzer
from network_scanning import NetworkScanner
from reporting import ReportGenerator
from enhanced_recon import EnhancedReconnaissance


class TestIntegration(unittest.TestCase):
    """Integration tests for complete workflows."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_ip = "127.0.0.1"
    
    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @patch('main.NetworkScanner.run_nmap_scan')
    @patch('main.validate_ip')
    def test_passive_recon_workflow(self, mock_validate, mock_scan):
        """Test complete passive reconnaissance workflow."""
        mock_validate.return_value = True
        mock_scan.return_value = ({}, [])
        
        analyzer = NetSpearNetworkAnalyzer()
        with patch.object(analyzer.enhanced_recon, 'passive_recon_parallel') as mock_recon:
            mock_recon.return_value = {
                "geoip": {"country": "US", "city": "Test"},
                "dns": {},
                "errors": []
            }
            analyzer._passive_recon(self.test_ip)
            
            # Verify recon was called
            mock_recon.assert_called_once()
            # Verify report was updated
            self.assertGreater(len(analyzer.reporter.report_data["recon"]), 0)
    
    @patch('main.NetworkScanner.run_nmap_scan')
    def test_scan_and_report_workflow(self, mock_scan):
        """Test scan to report generation workflow."""
        mock_scan.return_value = ({
            "ports": [{"port": 80, "state": "open", "service": "http"}],
            "host_state": "up"
        }, [])
        
        scanner = NetworkScanner()
        reporter = ReportGenerator()
        
        scan_result, vulns = scanner.run_nmap_scan(self.test_ip, "quick")
        reporter.add_scan(self.test_ip, "Test Scan", scan_result, vulns)
        
        # Verify data was added
        self.assertEqual(len(reporter.report_data["scans"]), 1)
        self.assertEqual(reporter.report_data["scans"][0]["target"], self.test_ip)
    
    @patch('subprocess.run')
    def test_enhanced_recon_parallel_execution(self, mock_subprocess):
        """Test enhanced reconnaissance parallel execution."""
        mock_subprocess.return_value = MagicMock(
            returncode=0,
            stdout="test output",
            stderr=""
        )
        
        recon = EnhancedReconnaissance({})
        with patch('enhanced_recon.safe_tool_check', return_value=True):
            result = recon.passive_recon_parallel("example.com", "domain")
            
            # Verify structure
            self.assertIn("geoip", result)
            self.assertIn("errors", result)
            # Verify parallel execution occurred
            self.assertGreater(mock_subprocess.call_count, 0)


if __name__ == '__main__':
    unittest.main()


