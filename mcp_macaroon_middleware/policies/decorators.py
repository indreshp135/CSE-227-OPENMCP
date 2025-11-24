import logging
from typing import Callable, Dict

logger = logging.getLogger(__name__)

# A global registry for policy enforcers
_POLICY_ENFORCERS: Dict[str, Callable] = {}

def policy_enforcer(tool_name: str):
    """
    A decorator to register a policy enforcement function for a specific tool.
    """
    def decorator(func: Callable):
        logger.debug(f"Registering policy enforcer for tool: {tool_name}")
        _POLICY_ENFORCERS[tool_name] = func
        return func
    return decorator

def get_enforcer(tool_name: str) -> Callable:
    """
    Retrieves a registered policy enforcer for a given tool name.
    """
    enforcer = _POLICY_ENFORCERS.get(tool_name)
    if enforcer:
        logger.debug(f"Retrieved enforcer for tool: {tool_name}")
    else:
        logger.debug(f"No enforcer found for tool: {tool_name}")
    return enforcer
