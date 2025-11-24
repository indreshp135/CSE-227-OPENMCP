import logging
from dataclasses import dataclass
from enum import Enum
from datetime import datetime

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
    field_path: str
    action: str
    expiry: datetime

    @classmethod
    def from_string(cls, caveat_string: str) -> "Caveat":
        """Parses a caveat string into a Caveat object."""
        logger.debug(f"Attempting to parse caveat string: {caveat_string}")
        parts = caveat_string.split(":", 4)
        if len(parts) != 5:
            logger.error(f"Invalid caveat format: '{caveat_string}'. Expected 5 parts, got {len(parts)}.")
            raise ValueError(f"Invalid caveat format: {caveat_string}")

        phase_str, tool_name, field_path, action, expiry_str = parts
        try:
            execution_phase = ExecutionPhase(phase_str)
            # The expiry string must be in ISO 8601 format, ending with 'Z' for UTC.
            # e.g., 2026-01-01T00:00:00Z
            if not expiry_str.endswith("Z"):
                raise ValueError("Expiry string must be in UTC and end with 'Z'.")
            expiry = datetime.fromisoformat(expiry_str.replace("Z", "+00:00"))
            logger.debug(f"Successfully parsed caveat components: phase={phase_str}, tool={tool_name}, field={field_path}, action={action}, expiry={expiry_str}")
        except (ValueError, TypeError) as e:
            logger.error(f"Invalid caveat component in '{caveat_string}': {e}")
            raise ValueError(f"Invalid caveat component in '{caveat_string}': {e}")

        return cls(
            raw=caveat_string,
            execution_phase=execution_phase,
            tool_name=tool_name,
            field_path=field_path,
            action=action,
            expiry=expiry,
        )
