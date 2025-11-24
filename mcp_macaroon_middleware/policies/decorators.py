import logging
from typing import Callable, Dict

logger = logging.getLogger(__name__)

# A global registry for policy enforcers
_POLICY_ENFORCERS: Dict[str, Callable] = {}

def policy_enforcer(policy_name: str):
    """
    A decorator to register a policy enforcement function for a specific policy.
    """
    def decorator(func: Callable):
        logger.debug(f"Registering policy enforcer: {policy_name}")
        _POLICY_ENFORCERS[policy_name] = func
        return func
    return decorator

def get_enforcer(policy_name: str) -> Callable:
    """
    Retrieves a registered policy enforcer for a given policy name.
    """
    enforcer = _POLICY_ENFORCERS.get(policy_name)
    if enforcer:
        logger.debug(f"Retrieved enforcer for policy: {policy_name}")
    else:
        logger.debug(f"No enforcer found for policy: {policy_name}")
    return enforcer