"""
Configuration file loader for NetSpear Network Analyzer.

Supports YAML and JSON configuration files with environment variable overrides.
"""
import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    logging.warning("PyYAML not available, YAML config files will not be supported")

from config import DEFAULT_TOOL_PATHS, REPORTS_DIR, MAX_SCAN_TIMEOUT, MAX_WORKERS


class ConfigLoader:
    """Loads and manages configuration from files and environment variables."""
    
    DEFAULT_CONFIG_PATHS = [
        Path.home() / ".netspear" / "config.yaml",
        Path.home() / ".netspear" / "config.json",
        Path.cwd() / "netspear.yaml",
        Path.cwd() / "netspear.json",
        Path(__file__).parent / "config.yaml",
        Path(__file__).parent / "config.json",
    ]
    
    def __init__(self, config_path: Optional[Path] = None):
        """
        Initialize configuration loader.
        
        Args:
            config_path: Optional explicit path to config file
        """
        self.config_path = config_path
        self.config: Dict[str, Any] = {}
        self._load_config()
    
    def _load_config(self) -> None:
        """Load configuration from file or defaults."""
        if self.config_path and self.config_path.exists():
            self._load_from_file(self.config_path)
        else:
            # Try to find config file in default locations
            for path in self.DEFAULT_CONFIG_PATHS:
                if path.exists():
                    self._load_from_file(path)
                    self.config_path = path
                    logging.info(f"Loaded configuration from {path}")
                    break
        
        # Apply environment variable overrides
        self._apply_env_overrides()
    
    def _load_from_file(self, path: Path) -> None:
        """Load configuration from a file."""
        try:
            if path.suffix == ".yaml" or path.suffix == ".yml":
                if not YAML_AVAILABLE:
                    logging.warning(f"YAML support not available, skipping {path}")
                    return
                with open(path, 'r') as f:
                    self.config = yaml.safe_load(f) or {}
            elif path.suffix == ".json":
                with open(path, 'r') as f:
                    self.config = json.load(f)
            else:
                logging.warning(f"Unsupported config file format: {path.suffix}")
        except Exception as e:
            logging.error(f"Failed to load config from {path}: {e}")
            self.config = {}
    
    def _apply_env_overrides(self) -> None:
        """Apply environment variable overrides to configuration."""
        # Tool paths
        for tool in DEFAULT_TOOL_PATHS.keys():
            env_var = f"{tool.upper().replace('-', '_')}_PATH"
            if os.getenv(env_var):
                self.config.setdefault("tool_paths", {})[tool] = os.getenv(env_var)
        
        # Other settings
        if os.getenv("NETSPEAR_REPORTS_DIR"):
            self.config["reports_dir"] = os.getenv("NETSPEAR_REPORTS_DIR")
        if os.getenv("NETSPEAR_MAX_WORKERS"):
            self.config["max_workers"] = int(os.getenv("NETSPEAR_MAX_WORKERS"))
        if os.getenv("NETSPEAR_SCAN_TIMEOUT"):
            self.config["max_scan_timeout"] = int(os.getenv("NETSPEAR_SCAN_TIMEOUT"))
    
    def get_tool_paths(self) -> Dict[str, str]:
        """Get tool paths from config or defaults."""
        tool_paths = DEFAULT_TOOL_PATHS.copy()
        if "tool_paths" in self.config:
            tool_paths.update(self.config["tool_paths"])
        return tool_paths
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value."""
        return self.config.get(key, default)
    
    def get_reports_dir(self) -> Path:
        """Get reports directory from config or default."""
        if "reports_dir" in self.config:
            return Path(self.config["reports_dir"])
        return REPORTS_DIR
    
    def get_max_workers(self) -> int:
        """Get max workers from config or default."""
        return self.config.get("max_workers", MAX_WORKERS)
    
    def get_scan_timeout(self) -> int:
        """Get scan timeout from config or default."""
        return self.config.get("max_scan_timeout", MAX_SCAN_TIMEOUT)


def create_default_config(path: Path, format: str = "yaml") -> None:
    """
    Create a default configuration file.
    
    Args:
        path: Path where to create the config file
        format: Format to use ('yaml' or 'json')
    """
    default_config = {
        "version": "2.0",
        "tool_paths": DEFAULT_TOOL_PATHS,
        "reports_dir": str(REPORTS_DIR),
        "max_workers": MAX_WORKERS,
        "max_scan_timeout": MAX_SCAN_TIMEOUT,
        "logging": {
            "level": "INFO",
            "format": "json",  # or "text"
            "file": None
        },
        "scan_defaults": {
            "mode": "SAFE",
            "stealth": False
        }
    }
    
    path.parent.mkdir(parents=True, exist_ok=True)
    
    if format == "yaml" and YAML_AVAILABLE:
        with open(path, 'w') as f:
            yaml.dump(default_config, f, default_flow_style=False, sort_keys=False)
    else:
        with open(path, 'w') as f:
            json.dump(default_config, f, indent=2)
    
    logging.info(f"Created default configuration at {path}")


