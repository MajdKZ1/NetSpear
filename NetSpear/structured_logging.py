"""
Structured logging system for NetSpear Network Analyzer.

Provides granular logging levels and JSON format support.
"""
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional
from enum import IntEnum


class LogLevel(IntEnum):
    """Extended logging levels for granular control."""
    TRACE = 5
    DEBUG = 10
    INFO = 20
    NOTICE = 25
    WARNING = 30
    ERROR = 40
    CRITICAL = 50


class StructuredFormatter(logging.Formatter):
    """JSON formatter for structured logging."""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_data: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "levelno": record.levelno,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        # Add extra fields
        if hasattr(record, "extra"):
            log_data.update(record.extra)
        
        return json.dumps(log_data, default=str)


class TextFormatter(logging.Formatter):
    """Enhanced text formatter with colors and structure."""
    
    COLORS = {
        'TRACE': '\033[36m',      # Cyan
        'DEBUG': '\033[94m',      # Blue
        'INFO': '\033[92m',       # Green
        'NOTICE': '\033[93m',    # Yellow
        'WARNING': '\033[93m',    # Yellow
        'ERROR': '\033[91m',      # Red
        'CRITICAL': '\033[95m',   # Magenta
        'RESET': '\033[0m'
    }
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as colored text."""
        level = record.levelname
        color = self.COLORS.get(level, self.COLORS['RESET'])
        reset = self.COLORS['RESET']
        
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        
        msg = f"{color}[{level:8}]{reset} {timestamp} | {record.name} | {record.getMessage()}"
        
        if record.exc_info:
            msg += f"\n{self.formatException(record.exc_info)}"
        
        return msg


def setup_structured_logging(
    level: int = logging.INFO,
    format_type: str = "text",
    log_file: Optional[Path] = None,
    enable_trace: bool = False
) -> None:
    """
    Set up structured logging system.
    
    Args:
        level: Logging level (logging.DEBUG, logging.INFO, etc.)
        format_type: Format type ('json' or 'text')
        log_file: Optional file path for logging
        enable_trace: Enable TRACE level logging
    """
    # Add TRACE level if enabled
    if enable_trace:
        logging.addLevelName(LogLevel.TRACE, "TRACE")
        logging.addLevelName(LogLevel.NOTICE, "NOTICE")
    
    # Remove existing handlers
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    
    # Set level
    root_logger.setLevel(level)
    
    # Create formatter
    if format_type.lower() == "json":
        formatter = StructuredFormatter()
    else:
        formatter = TextFormatter(
            fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # File handler if specified
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    
    logging.info("Structured logging initialized", extra={
        "format": format_type,
        "level": logging.getLevelName(level),
        "log_file": str(log_file) if log_file else None
    })


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance with structured logging support.
    
    Args:
        name: Logger name
    
    Returns:
        Logger instance
    """
    logger = logging.getLogger(name)
    
    # Add convenience methods
    def trace(msg: str, *args, **kwargs):
        """Log at TRACE level."""
        if logger.isEnabledFor(LogLevel.TRACE):
            logger._log(LogLevel.TRACE, msg, args, **kwargs)
    
    def notice(msg: str, *args, **kwargs):
        """Log at NOTICE level."""
        if logger.isEnabledFor(LogLevel.NOTICE):
            logger._log(LogLevel.NOTICE, msg, args, **kwargs)
    
    logger.trace = trace
    logger.notice = notice
    
    return logger


