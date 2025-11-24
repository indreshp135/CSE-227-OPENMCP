import logging
import os
from fastmcp.server.middleware import Middleware
from fastmcp.server.dependencies import get_access_token
from pymacaroons import Macaroon
from ..exceptions import MacaroonMiddlewareError, DeserializationError
from .policy_engine import PolicyEngine, ExecutionPhase
from ..validators.caveat_validator import CaveatValidator
from ..config.loader import load_policies_from_yaml

logger = logging.getLogger(__name__)
SECRET_KEY = os.environ.get("MACAROON_SECRET_KEY", "this_is_a_secret_key")

class MacaroonMiddleware(Middleware):
    """
    A production-grade middleware for macaroon-based policy enforcement.
    """

    def __init__(self, config_path: str):
        logger.info("Initializing MacaroonMiddleware.")
        self._policy_engine = PolicyEngine(CaveatValidator())
        self._initial_caveats = load_policies_from_yaml(config_path)
        self._token_to_macaroon = {}  # In-memory cache
        logger.info(f"MacaroonMiddleware initialized with {len(self._initial_caveats)} initial caveats.")

    async def on_call_tool(self, context, call_next):
        """
        The main middleware logic for handling tool calls.
        """
        logger.debug(f"on_call_tool started for tool: {context.message.name}")
        try:
            token = get_access_token()
            user_id = token.claims.get("login", "unknown_user")
            token_id = f"{user_id}_{hash(str(token.claims))}"
            logger.debug(f"Authenticated user_id: {user_id}, token_id: {token_id}")
        except Exception as e:
            logger.error(f"Failed to get access token: {e}")
            raise MacaroonMiddlewareError(f"Failed to get access token: {e}")

        macaroon = self._get_or_create_macaroon(token_id, user_id)
        logger.debug(f"Macaroon obtained for user {user_id}.")

        # Pre-execution policy enforcement
        logger.debug(f"Enforcing pre-execution policies for tool: {context.message.name}")
        self._policy_engine.enforce_policies(
            macaroon=macaroon,
            tool_name=context.message.name,
            phase=ExecutionPhase.BEFORE,
            context=context,
        )
        logger.debug(f"Pre-execution policies enforced for tool: {context.message.name}")

        result = await call_next(context)
        logger.debug(f"Tool '{context.message.name}' executed. Result obtained.")

        # Post-execution policy enforcement
        logger.debug(f"Enforcing post-execution policies for tool: {context.message.name}")
        self._policy_engine.enforce_policies(
            macaroon=macaroon,
            tool_name=context.message.name,
            phase=ExecutionPhase.AFTER,
            context=context,
            result=result,
        )
        logger.debug(f"Post-execution policies enforced for tool: {context.message.name}")

        return result
    
    def _get_or_create_macaroon(self, token_id: str, user_id: str) -> Macaroon:
        """
        Retrieves a macaroon from the cache or creates a new one.
        """
        if token_id in self._token_to_macaroon:
            logger.debug(f"Retrieving macaroon from cache for token_id: {token_id}")
            serialized_macaroon = self._token_to_macaroon[token_id]
            try:
                return Macaroon.deserialize(serialized_macaroon)
            except Exception as e:
                logger.error(f"Failed to deserialize cached macaroon for token_id {token_id}: {e}")
                raise DeserializationError("Failed to deserialize cached macaroon.")

        logger.debug(f"Creating new base macaroon for user_id: {user_id}")
        macaroon = self._create_base_macaroon(user_id)
        self._token_to_macaroon[token_id] = macaroon.serialize()
        logger.debug(f"New macaroon created and cached for user_id: {user_id}")
        return macaroon

    def _create_base_macaroon(self, user_id: str) -> Macaroon:
        """
        Creates a new base macaroon with initial caveats from the config.
        """
        macaroon = Macaroon(
            location="mcp_server",
            identifier=f"user_{user_id}",
            key=SECRET_KEY,
        )
        macaroon.add_first_party_caveat(f"user_id = {user_id}")
        logger.debug(f"Added base user_id caveat: user_id = {user_id}")

        for caveat_str in self._initial_caveats:
            macaroon.add_first_party_caveat(caveat_str)
            logger.debug(f"Added initial caveat from config: {caveat_str}")

        return macaroon
