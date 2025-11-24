"""
MCP Macaroon Middleware - A production-grade policy enforcement layer for MCP.
"""

import logging

# Configure logging for the package
logging.getLogger(__name__).addHandler(logging.NullHandler())

# Import core components
from .core.middleware import MacaroonMiddleware
from .core.policy_engine import PolicyEngine

# Import models
from .models.caveat import ExecutionPhase, Caveat, ActionType

# Import policies
from .policies.decorators import policy_enforcer
from .policies import default_enforcers

# Import exceptions
from .exceptions import MacaroonMiddlewareError, PolicyViolationError

# Import helpers
from .helpers import extract_content_to_dicts, update_result_with_dicts

# Define the public API of the package
__all__ = [
    "MacaroonMiddleware",
    "PolicyEngine",
    "ExecutionPhase",
    "Caveat",
    "ActionType",
    "policy_enforcer",
    "MacaroonMiddlewareError",
    "PolicyViolationError",
    "extract_content_to_dicts",
    "update_result_with_dicts",
]