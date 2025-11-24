import logging
from dataclasses import dataclass
from enum import Enum
from datetime import datetime, timezone
from typing import Tuple, Optional

logger = logging.getLogger(__name__)

class ExecutionPhase(Enum):
    """Enum for the execution phase of a policy."""
    BEFORE = "bf"
    AFTER = "af"
    
class ActionType(Enum):
    """Enum for the action type of a policy."""
    ALLOW = "allow"
    DENY = "deny"
    ELICIT = "elicit"

@dataclass
class Caveat:
    """Represents a parsed macaroon caveat."""
    raw: str
    execution_phase: ExecutionPhase
    tool_name: str
    policy_name: str
    action: ActionType
    params: Tuple[str, ...]
    expiry: Optional[datetime] = None

    @classmethod
    def from_string(cls, caveat_string: str) -> "Caveat":
        """Parses a caveat string into a Caveat object."""
        logger.debug(f"Attempting to parse caveat string: {caveat_string}")
        parts = caveat_string.split(":")
        if len(parts) < 4:
            logger.error(f"Invalid caveat format: '{caveat_string}'. Expected at least 4 parts, got {len(parts)}.")
            raise ValueError(f"Invalid caveat format: {caveat_string}")

        phase_str = parts[0]
        tool_name = parts[1]
        policy_name = parts[2]
        action_str = parts[3]
        
        params_parts = list(parts[4:])
        expiry = None
        
        if params_parts and params_parts[-1].startswith("time<"):
            time_part = params_parts.pop()
            try:
                expiry_str = time_part.split("<")[1]
                expiry = datetime.strptime(expiry_str, '%Y%m%dT%H%M%SZ').replace(tzinfo=timezone.utc)
            except (IndexError, ValueError) as e:
                logger.warning(f"Invalid time format in caveat '{caveat_string}': {e}")

        params = tuple(params_parts)

        try:
            execution_phase = ExecutionPhase(phase_str)
            action = ActionType(action_str)
            logger.debug(f"Successfully parsed caveat: phase={phase_str}, tool={tool_name}, policy={policy_name}, action={action}, params={params}, expiry={expiry}")
        except ValueError as e:
            logger.error(f"Invalid execution phase or action in '{caveat_string}': {e}")
            raise ValueError(f"Invalid execution phase or action in '{caveat_string}': {e}")

        return cls(
            raw=caveat_string,
            execution_phase=execution_phase,
            tool_name=tool_name,
            policy_name=policy_name,
            action=action,
            params=params,
            expiry=expiry,
        )