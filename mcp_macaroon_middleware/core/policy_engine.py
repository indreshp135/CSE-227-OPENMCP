import logging
from typing import List, Any
from pymacaroons import Macaroon
from ..models.caveat import Caveat, ExecutionPhase
from ..validators.caveat_validator import CaveatValidator
from ..policies.decorators import get_enforcer
from ..exceptions import PolicyViolationError, CaveatValidationError

logger = logging.getLogger(__name__)

class PolicyEngine:
    """
    The policy engine responsible for enforcing macaroon caveats.
    """

    def __init__(self, validator: CaveatValidator):
        self._validator = validator
        logger.info("PolicyEngine initialized.")

    def enforce_policies(
        self,
        macaroon: Macaroon,
        tool_name: str,
        phase: ExecutionPhase,
        context: Any = None,
        result: Any = None,
    ):
        """
        Enforces policies for a given tool call and execution phase.
        """
        logger.debug(f"Enforcing policies for tool '{tool_name}' in phase '{phase.value}'.")
        caveats = self._get_applicable_caveats(macaroon, tool_name, phase)
        logger.debug(f"Found {len(caveats)} applicable caveats for tool '{tool_name}' in phase '{phase.value}'.")

        for caveat in caveats:
            logger.debug(f"Processing caveat: {caveat.raw}")
            try:
                self._validator.validate(caveat)
                logger.debug(f"Caveat '{caveat.raw}' validated successfully.")
                enforcer = get_enforcer(caveat.policy_name)
                if enforcer:
                    logger.debug(f"Executing enforcer for policy '{caveat.policy_name}' with caveat: {caveat.raw}")
                    enforcer(
                        caveat,
                        context.fastmcp_context if context else None,
                        result,
                        *caveat.params
                    )
                    logger.debug(f"Enforcer for '{caveat.policy_name}' executed successfully.")
                else:
                    logger.warning(f"No enforcer registered for policy '{caveat.policy_name}'. Skipping caveat: {caveat.raw}")
            except (CaveatValidationError, PolicyViolationError) as e:
                logger.error(f"Policy enforcement failed for caveat '{caveat.raw}': {e}")
                raise e
            except Exception as e:
                logger.exception(f"An unexpected error occurred during policy enforcement for caveat '{caveat.raw}'.")
                raise PolicyViolationError(f"Error enforcing caveat '{caveat.raw}': {e}")

    def _get_applicable_caveats(
        self, macaroon: Macaroon, tool_name: str, phase: ExecutionPhase
    ) -> List[Caveat]:
        """
        Parses and filters caveats that are applicable to the current context.
        """
        applicable_caveats = []
        for caveat_obj in macaroon.caveats:
            caveat_str = caveat_obj.caveat_id
            try:
                caveat = Caveat.from_string(caveat_str)
                if (
                    caveat.tool_name == tool_name
                    and caveat.execution_phase == phase
                ):
                    applicable_caveats.append(caveat)
                    logger.debug(f"Added applicable caveat: {caveat.raw}")
            except ValueError as e:
                logger.warning(f"Ignoring malformed caveat '{caveat_str}': {e}")
            except Exception as e:
                logger.exception(f"An unexpected error occurred while processing caveat '{caveat_str}'.")
        return applicable_caveats