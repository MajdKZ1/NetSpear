"""
Example reconnaissance plugin for NetSpear.

This demonstrates how to create a custom plugin.
"""
from plugin_system import ReconPlugin
import logging


class ExampleReconPlugin(ReconPlugin):
    """Example reconnaissance plugin."""
    
    def __init__(self):
        super().__init__(
            name="example_recon",
            version="1.0.0",
            description="Example reconnaissance plugin for demonstration"
        )
        self.logger = logging.getLogger(__name__)
    
    def initialize(self, context: Dict[str, Any]) -> bool:
        """Initialize the plugin."""
        self.logger.info("Example recon plugin initialized")
        return True
    
    def gather_intel(self, target: str, target_type: str) -> Dict[str, Any]:
        """
        Gather intelligence on target.
        
        This is a simple example - real plugins would perform actual reconnaissance.
        """
        self.logger.info(f"Example plugin gathering intel on {target} ({target_type})")
        
        return {
            "plugin": self.name,
            "target": target,
            "target_type": target_type,
            "data": {
                "example_field": "example_value",
                "note": "This is example data from a plugin"
            }
        }
    
    def execute(self, *args, **kwargs) -> Any:
        """Execute plugin functionality."""
        if args:
            target = args[0]
            target_type = kwargs.get("target_type", "ip")
            return self.gather_intel(target, target_type)
        return {}


