"""
Models for the MCP Macaroon Middleware.
"""
import logging

# Configure logging for the package
logging.getLogger(__name__).addHandler(logging.NullHandler())

from .caveat import Caveat, ExecutionPhase, ActionType

__all__ = ["Caveat", "ExecutionPhase", "ActionType"]