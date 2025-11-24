import logging
from typing import List
from ..models.caveat import Caveat, ActionType
from ..exceptions import PolicyViolationError
from .decorators import policy_enforcer
from ..helpers import extract_content_to_dicts, update_result_with_dicts
from pymacaroons import Macaroon
from fastmcp import Context
from fastmcp.tools.tool import ToolResult

logger = logging.getLogger(__name__)

@policy_enforcer("tool_access")
def enforce_tool_access_policy(caveat: Caveat, context: Context, result: ToolResult, macaroon: Macaroon) -> List[Caveat]:
    """Enforces tool-level access control."""
    logger.info(f"Enforcing policy for {caveat.tool_name}: {caveat.raw}")
    if caveat.action == ActionType.ALLOW:
        pass
    elif caveat.action == ActionType.DENY:
        raise PolicyViolationError(f"Access to tool '{caveat.tool_name}' is denied")
    
    return []

@policy_enforcer("field_access")
def enforce_field_access_policy(caveat: Caveat, context: Context, result: ToolResult, macaroon: Macaroon, *fields) -> List[Caveat]:
    """Enforces field-level policies on tool results."""
    logger.info(f"Enforcing field access policy for {caveat.tool_name}: {caveat.raw}")
    
    if caveat.action == ActionType.DENY and result and result.content:
        try:
            tool_result_dict = extract_content_to_dicts(result)
            
            if not tool_result_dict:
                logger.debug("No data extracted, skipping redaction.")
                return []

            modifications_made = False
            for item in tool_result_dict:
                for field in fields:
                    if field in item and item[field] != "REDACTED":
                        item[field] = "REDACTED"
                        modifications_made = True
            
            if modifications_made:
                update_result_with_dicts(result, tool_result_dict)
                logger.debug(f"Successfully redacted fields: {fields}")
            else:
                logger.debug("Policy enforced, but no requested fields were present to redact.")

        except Exception as e:
            logger.error(f"Error executing field redaction policy: {e}", exc_info=True)
            
    elif caveat.action == ActionType.ALLOW:
        logger.debug("Allow action specified; no redaction performed.")
        pass
    else:
        logger.warning(f"Unknown action '{caveat.action}' specified; no changes made.")
    
    return []

@policy_enforcer("allow_attempts")
def enforce_allow_attempts_policy(caveat: Caveat, context: Context, result: ToolResult, macaroon: Macaroon, *args) -> List[Caveat]:
    """Enforces the attempts policy for a tool."""
    logger.info(f"Enforcing attempts policy for {caveat.tool_name}: {caveat.raw}")

    attempts_caveats = [
        c for c in macaroon.caveats
        if c.caveat_id.startswith(f"bf:{caveat.tool_name}:allow_attempts:allow:")
    ]

    if not attempts_caveats:
        return []

    lowest_attempt = -1
    for c in attempts_caveats:
        try:
            count = int(c.caveat_id.split(":")[-1])
            if lowest_attempt == -1 or count < lowest_attempt:
                lowest_attempt = count
        except (ValueError, IndexError):
            continue
    
    if lowest_attempt == 0:
        raise PolicyViolationError(f"No more attempts left for tool '{caveat.tool_name}'.")
    
    if lowest_attempt > 0:
        new_count = lowest_attempt - 1
        new_caveat_str = f"bf:{caveat.tool_name}:allow_attempts:allow:{new_count}"
        if not any(c.caveat_id == new_caveat_str for c in macaroon.caveats):
            return [Caveat.from_string(new_caveat_str)]

    return []
