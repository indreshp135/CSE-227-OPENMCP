import logging
from typing import List
from pymacaroons import Macaroon, Verifier
from ..models.caveat import Caveat, ExecutionPhase, ActionType
from ..validators.caveat_validator import CaveatValidator
from ..policies.decorators import get_enforcer
from ..exceptions import PolicyViolationError, CaveatValidationError
from datetime import datetime, timedelta, timezone
from fastmcp import Context
from fastmcp.server.elicitation import AcceptedElicitation
from fastmcp.tools.tool import ToolResult
from fastmcp.server.middleware.middleware import MiddlewareContext, mt

logger = logging.getLogger(__name__)

class PolicyEngine:
    """
    The policy engine responsible for enforcing macaroon caveats.
    """

    def __init__(self, validator: CaveatValidator, elicit_expiry: int, secret_key: str):
        self._validator = validator
        self._elicit_expiry = elicit_expiry
        self._secret_key = secret_key
        logger.info("PolicyEngine initialized.")

    def verify_macaroon(self, macaroon: Macaroon, user_id: str) -> bool:
        """Verify macaroon integrity and all its caveats."""
        logger.debug("Verifying macaroon integrity and caveats")
        verifier = Verifier()
        for caveat in macaroon.caveats:
            try:
                caveat_obj = Caveat.from_string(caveat.caveat_id)
                self._validator.validate(caveat_obj)
                verifier.satisfy_exact(caveat.caveat_id)
            except CaveatValidationError as e:
                logger.error(f"Caveat validation failed: {e}")
                return False
            except ValueError:
                logger.warning(f"Skipping non-policy caveat: {caveat.caveat_id}")
        try:
            return verifier.verify(macaroon, self._secret_key)
        except Exception as e:
            logger.exception(f"Macaroon verification failed: {e}")
            return False

    def _add_list_of_caveats(self, macaroon: Macaroon, caveat_strs: List[Caveat]):
        """Adds a list of caveats to the macaroon."""
        for caveat_str in caveat_strs:
            macaroon.add_first_party_caveat(caveat_str.raw)
            logger.info(f"Added caveat to macaroon: {caveat_str.raw}")

    async def enforce_policies(
        self,
        macaroon: Macaroon,
        tool_name: str,
        phase: ExecutionPhase,
        context: MiddlewareContext[mt.CallToolRequestParams] = None,
        result: ToolResult = None,
        user_id: str = None
    ) -> Macaroon:
        """
        Enforces policies for a given tool call and execution phase.
        """
        logger.debug(f"Enforcing policies for tool '{tool_name}' in phase '{phase.value}'.")

        if not self.verify_macaroon(macaroon, user_id):
            raise PolicyViolationError("Macaroon verification failed.")

        caveats = self._get_applicable_caveats(macaroon, tool_name, phase)
        logger.debug(f"Found {len(caveats)} applicable caveats for tool '{tool_name}' in phase '{phase.value}'.")

        final_caveats = await self._process_caveats(caveats, macaroon, context, result)
        self._add_list_of_caveats(macaroon, final_caveats)
        return macaroon

    async def _process_caveats(
        self, caveats: List[Caveat], macaroon: Macaroon, context: MiddlewareContext[mt.CallToolRequestParams], result: ToolResult
    ) -> List[Caveat]:
        """Process and enforce all applicable caveats."""
        new_caveats = []

        for caveat in caveats:
            logger.debug(f"Processing caveat: {caveat.raw}")
            try:
                if caveat.action == ActionType.ELICIT:
                    elicited_caveat = await self._handle_elicit_action(macaroon, caveat, context.fastmcp_context)
                    if elicited_caveat:
                        new_caveats.extend(self._execute_enforcer(elicited_caveat, context, result, macaroon))
                        new_caveats.append(elicited_caveat)
                else:
                    new_caveats.extend(self._execute_enforcer(caveat, context, result, macaroon))
            except (CaveatValidationError, PolicyViolationError) as e:
                logger.error(f"Policy enforcement failed for caveat '{caveat.raw}': {e}")
                raise e
            except Exception as e:
                logger.exception(f"Unexpected error during policy enforcement for caveat '{caveat.raw}'.")
                raise PolicyViolationError(f"Error enforcing caveat '{caveat.raw}': {e}")

        return new_caveats

    def _execute_enforcer(self, caveat: Caveat, context: MiddlewareContext[mt.CallToolRequestParams], result: ToolResult, macaroon: Macaroon) -> List[Caveat]:
        """Execute the enforcer for a given caveat."""
        enforcer = get_enforcer(caveat.policy_name)
        if enforcer:
            logger.debug(f"Executing enforcer for policy '{caveat.policy_name}' with caveat: {caveat.raw}")
            return enforcer(caveat, context, result,macaroon, *caveat.params)
        else:
            logger.warning(f"No enforcer registered for policy '{caveat.policy_name}'. Skipping caveat: {caveat.raw}")
            return []

    async def _handle_elicit_action(self, macaroon: Macaroon, caveat: Caveat, context: Context) -> List[Caveat]:
        """Handles the elicit action for a caveat."""
        if self._has_valid_allow_or_deny_caveat(macaroon, caveat):
            return []

        return await self._elicit_permission(caveat, context)

    def _has_valid_allow_or_deny_caveat(self, macaroon: Macaroon, caveat: Caveat) -> bool:
        """Check if a valid allow or deny caveat already exists."""
        base_caveat_str = caveat.raw
        allow_caveat_str = base_caveat_str.replace(ActionType.ELICIT.value, ActionType.ALLOW.value)
        deny_caveat_str = base_caveat_str.replace(ActionType.ELICIT.value, ActionType.DENY.value)

        has_valid_caveat = False
        for c in macaroon.caveats:
            if c.caveat_id.startswith(allow_caveat_str) or c.caveat_id.startswith(deny_caveat_str):
                try:
                    existing_caveat = Caveat.from_string(c.caveat_id)
                    if existing_caveat.expiry and datetime.now(timezone.utc) > existing_caveat.expiry:
                        logger.debug(f"Existing caveat '{c.caveat_id}' is expired. Re-eliciting permission.")
                        continue
                    logger.debug(f"Valid allow or deny caveat exists for '{caveat.raw}'.")
                    has_valid_caveat = True
                except ValueError:
                    logger.warning(f"Malformed caveat '{c.caveat_id}' encountered. Ignoring.")
        return has_valid_caveat

    async def _elicit_permission(self, caveat: Caveat, context: Context) -> Caveat:
        """Elicit permission from the user."""
        resp = await context.elicit(
            f"Grant permission for: {caveat.raw}?",
            response_type=bool
        )

        expiry = datetime.now(timezone.utc) + timedelta(seconds=self._elicit_expiry)
        time_str = f":time<{expiry.strftime('%Y%m%dT%H%M%SZ')}"

        if isinstance(resp, AcceptedElicitation) and resp.data:
            return Caveat.from_string(f"{caveat.raw.replace(ActionType.ELICIT.value, ActionType.ALLOW.value)}{time_str}")
        return Caveat.from_string(f"{caveat.raw.replace(ActionType.ELICIT.value, ActionType.DENY.value)}{time_str}")

    def _get_applicable_caveats(
        self, macaroon: Macaroon, tool_name: str, phase: ExecutionPhase
    ) -> List[Caveat]:
        """Parses and filters caveats that are applicable to the current context and not expired."""
        applicable_caveats = []
        for caveat_obj in macaroon.caveats:
            try:
                caveat = Caveat.from_string(caveat_obj.caveat_id)
                if (
                    caveat.tool_name == tool_name 
                    and caveat.execution_phase == phase
                    and (not caveat.expiry or datetime.now(timezone.utc) <= caveat.expiry)
                ):
                    applicable_caveats.append(caveat)
                    logger.debug(f"Added applicable caveat: {caveat.raw}")
            except ValueError:
                pass  # Ignore caveats not meant for this parser
            except Exception as e:
                logger.exception(f"Unexpected error while processing caveat '{caveat_obj.caveat_id}'.")
        return applicable_caveats
