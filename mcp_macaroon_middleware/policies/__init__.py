"""
Policies module for the MCP Macaroon Middleware.
"""
import logging

# Configure logging for the package
logging.getLogger(__name__).addHandler(logging.NullHandler())

from .decorators import policy_enforcer, get_enforcer

__all__ = ["policy_enforcer", "get_enforcer"]
