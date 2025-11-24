"""
Custom exceptions for the MCP Macaroon Middleware.
"""
import logging

# Configure logging for the package
logging.getLogger(__name__).addHandler(logging.NullHandler())

class MacaroonMiddlewareError(Exception):
    """Base exception for all middleware errors."""
    pass

class PolicyViolationError(MacaroonMiddlewareError):
    """Raised when a policy is violated."""
    pass

class CaveatValidationError(MacaroonMiddlewareError):
    """Raised when a caveat validation fails."""
    pass

class ConfigurationError(MacaroonMiddlewareError):
    """Raised for configuration-related errors."""
    pass

class DeserializationError(MacaroonMiddlewareError):
    """Raised when a macaroon cannot be deserialized."""
    pass
