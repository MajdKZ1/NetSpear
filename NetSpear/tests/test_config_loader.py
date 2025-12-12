"""
Unit tests for configuration loader.
"""
import unittest
from unittest.mock import patch, mock_open
import sys
from pathlib import Path
import tempfile
import json

sys.path.insert(0, str(Path(__file__).parent.parent))

from config_loader import ConfigLoader, create_default_config


class TestConfigLoader(unittest.TestCase):
    """Test cases for ConfigLoader."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.config_file = Path(self.temp_dir) / "test_config.json"
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_load_json_config(self):
        """Test loading JSON configuration."""
        config_data = {
            "version": "2.0",
            "max_workers": 8,
            "tool_paths": {"nmap": "/custom/path/nmap"}
        }
        
        with open(self.config_file, 'w') as f:
            json.dump(config_data, f)
        
        loader = ConfigLoader(self.config_file)
        self.assertEqual(loader.get("max_workers"), 8)
        self.assertEqual(loader.get_tool_paths()["nmap"], "/custom/path/nmap")
    
    def test_create_default_config(self):
        """Test creating default configuration."""
        config_path = Path(self.temp_dir) / "config.json"
        create_default_config(config_path, "json")
        
        self.assertTrue(config_path.exists())
        
        with open(config_path, 'r') as f:
            config = json.load(f)
            self.assertEqual(config["version"], "2.0")
            self.assertIn("tool_paths", config)


if __name__ == '__main__':
    unittest.main()


