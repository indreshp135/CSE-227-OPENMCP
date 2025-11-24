import logging
from typing import List, Any
from pymacaroons import Macaroon, Verifier
from ..models.caveat import Caveat, ExecutionPhase, ActionType
from ..validators.caveat_validator import CaveatValidator
from ..policies.decorators import get_enforcer
from ..exceptions import PolicyViolationError, CaveatValidationError
from datetime import datetime, timedelta
from fastmcp import Context
from fastmcp.server.elicitation import AcceptedElicitation
from fastmcp.tools.tool import ToolResult

logger = logging.getLogger(__name__)

class PolicyEngine:
    """
    The policy engine responsible for enforcing macaroon caveats.
    """

    def __init__(self, validator: CaveatValidator, app: Any, elicit_expiry: int, secret_key: str):
        self._validator = validator
        self._app = app
        self._elicit_expiry = elicit_expiry
        self._secret_key = secret_key
        logger.info("PolicyEngine initialized.")
        
    def verify_macaroon(self, macaroon: Macaroon, secret_key: str) -> bool:
        """Verify macaroon integrity and base requirements."""
        logger.debug("Verifying macaroon integrity and caveats")
        try:
            v = Verifier()
            
            # Satisfy all caveats dynamically
            for caveat in macaroon.caveats:
                caveat_id = caveat.caveat_id
                if caveat_id.startswith("user_id = "):
                    v.satisfy_exact(caveat_id)
            
            v.verify(macaroon, secret_key)
            logger.info("Macaroon verification successful")
            return True
        except Exception as e:
            logger.exception(f"Macaroon verification failed: {e}")
            return False


    async def enforce_policies(
        self,
        macaroon: Macaroon,
        tool_name: str,
        phase: ExecutionPhase,
        context: Context = None,
        result: ToolResult = None,
        user_id: str = None
    ) -> Macaroon:
        """
        Enforces policies for a given tool call and execution phase.
        """
        logger.debug(f"Enforcing policies for tool '{tool_name}' in phase '{phase.value}'.")
        
        verified = self.verify_macaroon(macaroon, self._secret_key)

        if not verified:
            raise PolicyViolationError("Macaroon verification failed.")

        caveats = self._get_applicable_caveats(macaroon, tool_name, phase)
        logger.debug(f"Found {len(caveats)} applicable caveats for tool '{tool_name}' in phase '{phase.value}'.")

        for caveat in caveats:
            logger.debug(f"Processing caveat: {caveat.raw}")
            try:
                if caveat.action == ActionType.ELICIT:
                    macaroon = await self._handle_elicit_action(macaroon, caveat, context)
                else:
                    self._validator.validate(caveat)
                    logger.debug(f"Caveat '{caveat.raw}' validated successfully.")
                    enforcer = get_enforcer(caveat.policy_name)
                    if enforcer:
                        logger.debug(f"Executing enforcer for policy '{caveat.policy_name}' with caveat: {caveat.raw}")
                        enforcer(
                            caveat,
                            context if context else None,
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
        return macaroon

    def _caveat_validator(self, caveat_str: str) -> bool:
        """General satisfier for all caveats."""
        try:
            caveat = Caveat.from_string(caveat_str)
            if caveat.expiry and datetime.now() > caveat.expiry:
                return False
        except ValueError:
            # Not a caveat this engine is responsible for
            pass
        return True

    async def _handle_elicit_action(self, macaroon: Macaroon, caveat: Caveat, context: Context) -> Macaroon:
        """Handles the elicit action for a caveat."""
        base_caveat_str = caveat.raw
        
        allow_caveat_str = base_caveat_str.replace(ActionType.ELICIT.value, ActionType.ALLOW.value)
        deny_caveat_str = base_caveat_str.replace(ActionType.ELICIT.value, ActionType.DENY.value)
        print(allow_caveat_str, deny_caveat_str)

        # Check if an 'allow' or 'deny' caveat already exists and if it is expired
        for c in macaroon.caveats:
            if c.caveat_id.startswith(allow_caveat_str) or c.caveat_id.startswith(deny_caveat_str):
                try:
                    existing_caveat = Caveat.from_string(c.caveat_id)
                    if existing_caveat.expiry and datetime.now() > existing_caveat.expiry:
                        logger.debug(f"Existing caveat '{c.caveat_id}' is expired. Re-eliciting permission.")
                        break
                    else:
                        logger.debug(f"Allow or deny caveat already exists and is valid for '{caveat.raw}'. Skipping elicitation.")
                        return
                except ValueError:
                    logger.warning(f"Malformed caveat '{c.caveat_id}' encountered. Ignoring and re-eliciting permission.")
                    break

        # Elicit permission from the user
        resp = await context.elicit(
            f"Grant permission for: {caveat.raw}?",
            response_type=bool
        )

        expiry = datetime.now() + timedelta(seconds=self._elicit_expiry)
        time_str = f":time<{expiry.strftime('%Y%m%dT%H%M%SZ')}"

        if isinstance(resp, AcceptedElicitation):
            macaroon.add_first_party_caveat(f"{allow_caveat_str}{time_str}")
            logger.info(f"Permission granted for '{caveat.raw}'. New caveats added.")
        else:
            macaroon.add_first_party_caveat(f"{deny_caveat_str}{time_str}")
            logger.info(f"Permission denied for '{caveat.raw}'. New deny caveat added.")
            raise PolicyViolationError(f"Permission denied for: {caveat.raw}")

        return macaroon

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