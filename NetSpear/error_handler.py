"""
Error handling utilities for NetSpear Network Analyzer.

Provides quick, concise error messages for common issues.
"""
import os
import sys
from pathlib import Path
from typing import Optional, Callable, Any
import logging

from utils import WHITE, RESET

class QuickError:
    """Quick error message handler for common issues."""
    
    @staticmethod
    def file_not_found(file_path: str, suggestion: Optional[str] = None) -> str:
        """Generate quick error message for missing file."""
        msg = f"✗ File not found: {file_path}"
        if suggestion:
            msg += f"\n  → {suggestion}"
        return msg
    
    @staticmethod
    def tool_not_found(tool: str, install_cmd: Optional[str] = None) -> str:
        """Generate quick error message for missing tool."""
        msg = f"✗ Tool not found: {tool}"
        if install_cmd:
            msg += f"\n  → Install: {install_cmd}"
        return msg
    
    @staticmethod
    def permission_denied(resource: str) -> str:
        """Generate quick error message for permission issues."""
        return f"✗ Permission denied: {resource}\n  → Run with sudo or check permissions"
    
    @staticmethod
    def network_error(operation: str, details: Optional[str] = None) -> str:
        """Generate quick error message for network issues."""
        msg = f"✗ Network error: {operation}"
        if details:
            msg += f"\n  → {details}"
        return msg
    
    @staticmethod
    def timeout_error(operation: str, timeout: int) -> str:
        """Generate quick error message for timeout."""
        return f"✗ Timeout: {operation} exceeded {timeout}s"
    
    @staticmethod
    def invalid_input(field: str, reason: Optional[str] = None) -> str:
        """Generate quick error message for invalid input."""
        msg = f"✗ Invalid {field}"
        if reason:
            msg += f": {reason}"
        return msg


def safe_file_check(file_path: str, must_exist: bool = True, 
                   on_error: Optional[Callable[[str], None]] = None) -> bool:
    """
    Safely check if a file exists with automatic error reporting.
    
    Args:
        file_path: Path to check
        must_exist: Whether file must exist
        on_error: Optional callback for error handling
    
    Returns:
        True if file exists (or doesn't need to), False otherwise
    """
    path = Path(file_path)
    if must_exist and not path.exists():
        error_msg = QuickError.file_not_found(str(path))
        print(WHITE + error_msg + RESET)
        if on_error:
            on_error(str(path))
        return False
    return True


def safe_tool_check(tool: str, install_hint: Optional[str] = None) -> bool:
    """
    Safely check if a tool is available with automatic error reporting.
    
    Args:
        tool: Tool name to check
        install_hint: Optional installation command hint
    
    Returns:
        True if tool is available, False otherwise
    """
    import shutil
    if not shutil.which(tool):
        error_msg = QuickError.tool_not_found(tool, install_hint)
        print(WHITE + error_msg + RESET)
        logging.debug(f"Tool not found: {tool}")
        return False
    return True


