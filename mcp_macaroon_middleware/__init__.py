"""
MCP Macaroon Middleware - A production-grade policy enforcement layer for MCP.
"""
import logging

__version__ = "1.0.0"

# Configure logging for the package
logging.getLogger(__name__).addHandler(logging.NullHandler())

from .core.middleware import MacaroonMiddleware
from .core.policy_engine import PolicyEngine
from .models.caveat import ExecutionPhase
from .policies.decorators import policy_enforcer
from .exceptions import MacaroonMiddlewareError, PolicyViolationError

__all__ = [
    "MacaroonMiddleware",
    "PolicyEngine",
    "ExecutionPhase",
    "policy_enforcer",
    "MacaroonMiddlewareError",
    "PolicyViolationError",
]