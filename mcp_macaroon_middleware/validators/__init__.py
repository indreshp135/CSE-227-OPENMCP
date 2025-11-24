"""
Validators module for the MCP Macaroon Middleware.
"""
import logging

# Configure logging for the package
logging.getLogger(__name__).addHandler(logging.NullHandler())

from .caveat_validator import CaveatValidator

__all__ = ["CaveatValidator"]
