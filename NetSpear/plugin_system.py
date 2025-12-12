"""
Plugin system for NetSpear Network Analyzer.

Allows extending functionality through plugins.
"""
import importlib
import importlib.util
import inspect
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Type, Callable
from abc import ABC, abstractmethod
import json

from utils import WHITE, RESET


class NetSpearPlugin(ABC):
    """Base class for NetSpear plugins."""
    
    def __init__(self, name: str, version: str, description: str = ""):
        """
        Initialize plugin.
        
        Args:
            name: Plugin name
            version: Plugin version
            description: Plugin description
        """
        self.name = name
        self.version = version
        self.description = description
        self.enabled = True
    
    @abstractmethod
    def initialize(self, context: Dict[str, Any]) -> bool:
        """
        Initialize the plugin.
        
        Args:
            context: Context dictionary with NetSpear components
        
        Returns:
            True if initialization successful
        """
        pass
    
    @abstractmethod
    def execute(self, *args, **kwargs) -> Any:
        """Execute plugin functionality."""
        pass
    
    def cleanup(self) -> None:
        """Cleanup plugin resources."""
        pass
    
    def get_info(self) -> Dict[str, Any]:
        """Get plugin information."""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "enabled": self.enabled
        }


class ReconPlugin(NetSpearPlugin):
    """Base class for reconnaissance plugins."""
    
    @abstractmethod
    def gather_intel(self, target: str, target_type: str) -> Dict[str, Any]:
        """
        Gather intelligence on target.
        
        Args:
            target: Target IP, domain, or URL
            target_type: Type of target
        
        Returns:
            Dictionary with intelligence data
        """
        pass


class ScanPlugin(NetSpearPlugin):
    """Base class for scanning plugins."""
    
    @abstractmethod
    def perform_scan(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform a scan.
        
        Args:
            target: Target to scan
            options: Scan options
        
        Returns:
            Scan results
        """
        pass


class ReportPlugin(NetSpearPlugin):
    """Base class for reporting plugins."""
    
    @abstractmethod
    def generate_report(self, data: Dict[str, Any], format: str) -> str:
        """
        Generate a report.
        
        Args:
            data: Data to include in report
            format: Report format
        
        Returns:
            Report content
        """
        pass


class PluginManager:
    """Manages NetSpear plugins."""
    
    def __init__(self, plugin_dir: Optional[Path] = None):
        """
        Initialize plugin manager.
        
        Args:
            plugin_dir: Directory containing plugins
        """
        self.plugin_dir = plugin_dir or Path(__file__).parent / "plugins"
        self.plugins: Dict[str, NetSpearPlugin] = {}
        self.loaded_plugins: List[str] = []
        self.context: Dict[str, Any] = {}
    
    def set_context(self, context: Dict[str, Any]) -> None:
        """Set context for plugins."""
        self.context = context
    
    def load_plugins(self) -> int:
        """
        Load all plugins from plugin directory.
        
        Returns:
            Number of plugins loaded
        """
        if not self.plugin_dir.exists():
            self.plugin_dir.mkdir(parents=True, exist_ok=True)
            logging.info(f"Created plugin directory: {self.plugin_dir}")
            return 0
        
        loaded = 0
        for plugin_file in self.plugin_dir.glob("*.py"):
            if plugin_file.name.startswith("_"):
                continue
            
            try:
                plugin = self._load_plugin(plugin_file)
                if plugin:
                    self.plugins[plugin.name] = plugin
                    self.loaded_plugins.append(plugin.name)
                    loaded += 1
                    logging.info(f"Loaded plugin: {plugin.name} v{plugin.version}")
            except Exception as e:
                logging.error(f"Failed to load plugin {plugin_file}: {e}")
        
        return loaded
    
    def _load_plugin(self, plugin_file: Path) -> Optional[NetSpearPlugin]:
        """Load a single plugin from file."""
        module_name = plugin_file.stem
        spec = importlib.util.spec_from_file_location(module_name, plugin_file)
        if not spec or not spec.loader:
            return None
        
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        # Find plugin class
        for name, obj in inspect.getmembers(module):
            if (inspect.isclass(obj) and 
                issubclass(obj, NetSpearPlugin) and 
                obj != NetSpearPlugin):
                plugin = obj()
                if plugin.initialize(self.context):
                    return plugin
        
        return None
    
    def get_plugin(self, name: str) -> Optional[NetSpearPlugin]:
        """Get a plugin by name."""
        return self.plugins.get(name)
    
    def get_plugins_by_type(self, plugin_type: Type[NetSpearPlugin]) -> List[NetSpearPlugin]:
        """Get all plugins of a specific type."""
        return [p for p in self.plugins.values() if isinstance(p, plugin_type) and p.enabled]
    
    def enable_plugin(self, name: str) -> bool:
        """Enable a plugin."""
        if name in self.plugins:
            self.plugins[name].enabled = True
            return True
        return False
    
    def disable_plugin(self, name: str) -> bool:
        """Disable a plugin."""
        if name in self.plugins:
            self.plugins[name].enabled = False
            return True
        return False
    
    def list_plugins(self) -> List[Dict[str, Any]]:
        """List all loaded plugins."""
        return [plugin.get_info() for plugin in self.plugins.values()]
    
    def cleanup_all(self) -> None:
        """Cleanup all plugins."""
        for plugin in self.plugins.values():
            try:
                plugin.cleanup()
            except Exception as e:
                logging.error(f"Error cleaning up plugin {plugin.name}: {e}")


# Plugin discovery utility
def discover_plugins(plugin_dir: Path) -> List[Dict[str, Any]]:
    """
    Discover available plugins without loading them.
    
    Args:
        plugin_dir: Directory to search
    
    Returns:
        List of plugin metadata
    """
    plugins = []
    if not plugin_dir.exists():
        return plugins
    
    for plugin_file in plugin_dir.glob("*.py"):
        if plugin_file.name.startswith("_"):
            continue
        
        try:
            # Try to extract metadata without full import
            with open(plugin_file, 'r') as f:
                content = f.read()
                # Simple regex-based extraction (could be improved)
                if "class" in content and "NetSpearPlugin" in content:
                    plugins.append({
                        "file": plugin_file.name,
                        "path": str(plugin_file)
                    })
        except Exception:
            pass
    
    return plugins

