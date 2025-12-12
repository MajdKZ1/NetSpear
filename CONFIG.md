# NetSpear Configuration Guide

NetSpear v2.0 supports configuration files in YAML or JSON format.

## Configuration File Locations

NetSpear searches for config files in this order:
1. `~/.netspear/config.yaml`
2. `~/.netspear/config.json`
3. `./netspear.yaml`
4. `./netspear.json`
5. `NetSpear/config.yaml`
6. `NetSpear/config.json`

## Creating a Config File

Use menu option `43` to create a default configuration file, or create one manually.

### Example YAML Config

```yaml
version: "2.0"
tool_paths:
  nmap: "nmap"
  msfvenom: "msfvenom"
  hydra: "hydra"
reports_dir: "/path/to/reports"
max_workers: 8
max_scan_timeout: 300
logging:
  level: "INFO"
  format: "json"  # or "text"
  file: "/path/to/netspear.log"
scan_defaults:
  mode: "SAFE"
  stealth: false
```

### Example JSON Config

```json
{
  "version": "2.0",
  "tool_paths": {
    "nmap": "nmap",
    "msfvenom": "msfvenom"
  },
  "reports_dir": "/path/to/reports",
  "max_workers": 8,
  "logging": {
    "level": "INFO",
    "format": "json"
  }
}
```

## Environment Variables

Environment variables override config file settings:
- `NMAP_PATH`, `MSFVENOM_PATH`, etc. for tool paths
- `NETSPEAR_REPORTS_DIR` for reports directory
- `NETSPEAR_MAX_WORKERS` for thread pool size
- `NETSPEAR_SCAN_TIMEOUT` for scan timeout

## Logging Configuration

### Log Levels
- `TRACE` (5) - Very detailed debugging
- `DEBUG` (10) - Debug information
- `INFO` (20) - Informational messages
- `NOTICE` (25) - Important notices
- `WARNING` (30) - Warning messages
- `ERROR` (40) - Error messages
- `CRITICAL` (50) - Critical errors

### Log Formats
- `text` - Human-readable colored output
- `json` - Structured JSON format for log aggregation


