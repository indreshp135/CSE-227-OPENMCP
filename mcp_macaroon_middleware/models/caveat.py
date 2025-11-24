import logging
from dataclasses import dataclass
from enum import Enum
from datetime import datetime
from typing import Tuple

logger = logging.getLogger(__name__)

class ExecutionPhase(Enum):
    """Enum for the execution phase of a policy."""
    BEFORE = "bf"
    AFTER = "af"

@dataclass
class Caveat:
    """Represents a parsed macaroon caveat."""
    raw: str
    execution_phase: ExecutionPhase
    tool_name: str
    policy_name: str
    action: str
    params: Tuple[str, ...]

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
        action = parts[3]
        params = tuple(parts[4:]) if len(parts) > 4 else ()

        try:
            execution_phase = ExecutionPhase(phase_str)
            logger.debug(f"Successfully parsed caveat: phase={phase_str}, tool={tool_name}, policy={policy_name}, action={action}, params={params}")
        except ValueError as e:
            logger.error(f"Invalid execution phase in '{caveat_string}': {e}")
            raise ValueError(f"Invalid execution phase in '{caveat_string}': {e}")

        return cls(
            raw=caveat_string,
            execution_phase=execution_phase,
            tool_name=tool_name,
            policy_name=policy_name,
            action=action,
            params=params,
        )