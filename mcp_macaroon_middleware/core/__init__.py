"""
Core components of the MCP Macaroon Middleware.
"""
import logging

# Configure logging for the package
logging.getLogger(__name__).addHandler(logging.NullHandler())

from .middleware import MacaroonMiddleware
from .policy_engine import PolicyEngine

__all__ = ["MacaroonMiddleware", "PolicyEngine"]