"""
Unit tests for plugin system.
"""
import unittest
from unittest.mock import Mock, patch, MagicMock
import sys
from pathlib import Path
import tempfile

sys.path.insert(0, str(Path(__file__).parent.parent))

from plugin_system import (
    NetSpearPlugin, ReconPlugin, PluginManager, 
    discover_plugins
)


class TestPlugin(ReconPlugin):
    """Test plugin for testing."""
    
    def __init__(self):
        super().__init__("test_plugin", "1.0.0", "Test plugin")
    
    def initialize(self, context):
        return True
    
    def gather_intel(self, target, target_type):
        return {"test": "data"}
    
    def execute(self, *args, **kwargs):
        return self.gather_intel(args[0] if args else "", kwargs.get("target_type", "ip"))


class TestPluginSystem(unittest.TestCase):
    """Test cases for plugin system."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.plugin_dir = Path(self.temp_dir) / "plugins"
        self.plugin_dir.mkdir(parents=True)
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_plugin_initialization(self):
        """Test plugin initialization."""
        plugin = TestPlugin()
        self.assertEqual(plugin.name, "test_plugin")
        self.assertEqual(plugin.version, "1.0.0")
        self.assertTrue(plugin.enabled)
    
    def test_plugin_manager(self):
        """Test plugin manager."""
        manager = PluginManager(self.plugin_dir)
        self.assertEqual(len(manager.plugins), 0)
        
        # Add plugin manually
        plugin = TestPlugin()
        plugin.initialize({})
        manager.plugins["test"] = plugin
        
        self.assertEqual(len(manager.plugins), 1)
        self.assertEqual(manager.get_plugin("test"), plugin)
    
    def test_plugin_enable_disable(self):
        """Test enabling and disabling plugins."""
        manager = PluginManager(self.plugin_dir)
        plugin = TestPlugin()
        plugin.initialize({})
        manager.plugins["test"] = plugin
        
        manager.disable_plugin("test")
        self.assertFalse(plugin.enabled)
        
        manager.enable_plugin("test")
        self.assertTrue(plugin.enabled)


if __name__ == '__main__':
    unittest.main()


