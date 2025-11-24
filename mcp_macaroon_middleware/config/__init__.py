"""
Configuration for the MCP Macaroon Middleware.
"""
import logging

# Configure logging for the package
logging.getLogger(__name__).addHandler(logging.NullHandler())

from .loader import load_config_from_yaml

__all__ = ["load_config_from_yaml"]