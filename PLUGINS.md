# NetSpear Plugin System

NetSpear v2.0 includes a powerful plugin system that allows you to extend functionality without modifying core code.

## Plugin Types

### ReconPlugin
Extends reconnaissance capabilities.

### ScanPlugin
Adds custom scanning methods.

### ReportPlugin
Custom report formats and generators.

## Creating a Plugin

1. Create a Python file in `NetSpear/plugins/`
2. Inherit from the appropriate plugin base class
3. Implement required methods

### Example Plugin

```python
from plugin_system import ReconPlugin

class MyReconPlugin(ReconPlugin):
    def __init__(self):
        super().__init__(
            name="my_recon",
            version="1.0.0",
            description="My custom reconnaissance plugin"
        )
    
    def initialize(self, context):
        # Access NetSpear components via context
        self.scanner = context.get("scanner")
        return True
    
    def gather_intel(self, target, target_type):
        # Your reconnaissance logic here
        return {"data": "your_intel_data"}
    
    def execute(self, *args, **kwargs):
        return self.gather_intel(args[0] if args else "", kwargs.get("target_type", "ip"))
```

## Plugin Management

Use menu option `42` to manage plugins:
- View loaded plugins
- Enable/disable plugins
- Reload plugins

## Plugin Context

Plugins receive a context dictionary with:
- `scanner`: NetworkScanner instance
- `reporter`: ReportGenerator instance
- `tool_paths`: Dictionary of tool paths
- `config`: Configuration dictionary


