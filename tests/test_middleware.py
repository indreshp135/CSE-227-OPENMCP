import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from mcp_macaroon_middleware import MacaroonMiddleware
from mcp.types import CallToolRequestParams
from fastmcp.server.middleware.middleware import MiddlewareContext
from mcp_macaroon_middleware.core.policy_engine import ExecutionPhase
from pymacaroons import Macaroon

@pytest.fixture
def middleware(policies_yaml_file):
    middleware = MacaroonMiddleware(config_path=str(policies_yaml_file))
    # Mock the policy engine's internal validator, as it's not the focus of these tests
    middleware._policy_engine._validator = MagicMock()
    middleware._policy_engine._validator.validate_caveat.return_value = None
    return middleware

def test_middleware_initialization(middleware, policies_yaml_file):
    assert middleware is not None
    assert middleware._secret_key == "test_secret_key"
    assert len(middleware._initial_caveats) == 2
    assert middleware._initial_caveats[0] == "bf:test_tool:tool_access:allow"

def test_create_base_macaroon(middleware):
    user_id = "test_user"
    macaroon = middleware._create_base_macaroon(user_id)
    assert macaroon is not None
    assert macaroon.location == "mcp_server"
    assert macaroon.identifier == f"user_{user_id}"
    
    caveats = [c.caveat_id for c in macaroon.caveats]
    assert "bf:test_tool:tool_access:allow" in caveats
    assert "af:test_tool:field_access:allow:some_field" in caveats

def test_get_or_create_macaroon(middleware):
    token_id = "test_token_id"
    user_id = "test_user"

    # 1. Create a new macaroon
    macaroon1 = middleware._get_or_create_macaroon(token_id, user_id)
    assert macaroon1 is not None
    assert token_id in middleware._token_to_macaroon

    # 2. Retrieve the same macaroon from cache
    macaroon2 = middleware._get_or_create_macaroon(token_id, user_id)
    assert macaroon2 is not None
    assert macaroon1.signature == macaroon2.signature

@pytest.mark.asyncio
async def test_on_call_tool(middleware):
    with patch("mcp_macaroon_middleware.core.middleware.get_access_token") as mock_get_token, \
         patch.object(middleware._policy_engine, "enforce_policies", new_callable=AsyncMock) as mock_enforce:

        # --- Setup Mocks ---
        mock_token = MagicMock()
        mock_token.claims = {"login": "test_user"}
        mock_get_token.return_value = mock_token

        mock_enforce.return_value = Macaroon(location="test", identifier="test", key="test")

        mock_fastmcp_context = MagicMock()
        # Simplified mock for CallToolRequestParams
        mock_call_tool_request = MagicMock(spec=CallToolRequestParams)
        mock_call_tool_request.name = "test_tool"

        mock_context = MiddlewareContext(
            message=mock_call_tool_request,
            fastmcp_context=mock_fastmcp_context
        )
        
        call_next = AsyncMock()
        call_next.return_value = "tool_result"

        # --- Call the method ---
        result = await middleware.on_call_tool(mock_context, call_next)

        # --- Assertions ---
        assert result == "tool_result"
        mock_get_token.assert_called_once()
        assert mock_enforce.call_count == 2
        
        before_call_args = mock_enforce.call_args_list[0].kwargs
        assert before_call_args["phase"] == ExecutionPhase.BEFORE
        assert before_call_args["tool_name"] == "test_tool"
        
        after_call_args = mock_enforce.call_args_list[1].kwargs
        assert after_call_args["phase"] == ExecutionPhase.AFTER
        assert after_call_args["tool_name"] == "test_tool"
        assert after_call_args["result"] == "tool_result"
        
        call_next.assert_awaited_once_with(mock_context)