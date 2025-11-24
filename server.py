import logging
import json
from typing import Dict, Any, List
from fastmcp import FastMCP, Context
from fastmcp.server.auth.providers.github import GitHubProvider
from fastmcp.server.dependencies import get_access_token
from mcp_macaroon_middleware import MacaroonMiddleware, policy_enforcer, PolicyViolationError, update_result_with_dicts, extract_content_to_dicts
import os
from mcp.types import TextContent

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Policy Enforcement ---

# server.py - Updated policy enforcers
@policy_enforcer("user_profile_fields")
def enforce_user_profile_policy(caveat, context, result, *fields):
    """Enforces field-level policies on get_user_profile."""
    logger.info(f"Enforcing policy for get_user_profile: {caveat.raw}")
    if caveat.action == "redact" and result:
        for field in fields:
            if field in result:
                result[field] = "REDACTED"
    elif caveat.action == "allow":
        pass

@policy_enforcer("tool_access")
def enforce_tool_access_policy(caveat, context, result):
    """Enforces tool-level access control."""
    logger.info(f"Enforcing policy for {caveat.tool_name}: {caveat.raw}")
    if caveat.action == "allow":
        pass
    elif caveat.action == "deny":
        raise PolicyViolationError(f"Access to tool '{caveat.tool_name}' is denied")

@policy_enforcer("email_fields")
def enforce_email_fields_policy(caveat, context, result, *fields):
    """Enforces field-level policies on read_emails."""
    logger.info(f"Enforcing policy for read_emails: {caveat.raw}")
    
    # Only proceed if the action is deny and there is a result to modify
    if caveat.action == "deny" and result and result.content:
        try:
            # 1. Extract current data as Python objects using the helper
            tool_result_dict = extract_content_to_dicts(result)
            
            if not tool_result_dict:
                logger.debug("No data extracted, skipping redaction.")
                return

            # 2. Modify data (Redact specified fields)
            modifications_made = False
            for email in tool_result_dict:
                for field in fields:
                    # Check if field exists and isn't already redacted to avoid redundant work
                    if field in email and email[field] != "REDACTED":
                        email[field] = "REDACTED"
                        modifications_made = True
            
            # 3. Re-serialize and update result ONLY if changes were made
            if modifications_made:
                # Serialize the modified Python list back to a JSON string
                update_result_with_dicts(result, tool_result_dict)
                logger.debug(f"Successfully redacted fields: {fields}")
            else:
                logger.debug("Policy enforced, but no requested fields were present to redact.")

        except Exception as e:
            logger.error(f"Error executing field redaction policy: {e}", exc_info=True)
            # Depending on security requirements, you might want to raise here 
            # to fail closed if redaction fails. For now, we log the error.
            # raise PolicyViolationError("Internal error during policy enforcement") from e

    elif caveat.action == "allow":
        pass
# --- Example Usage ---

def create_mcp_server_with_macaroon_auth():
    """Create MCP server with GitHub auth and macaroon middleware."""
    logger.info("Creating MCP server with Macaroon authentication")

    # Load GitHub OAuth credentials
    GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID")
    GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET")
    BASE_URL = os.environ.get("BASE_URL", "http://localhost:9001")

    if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
        logger.error("GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET must be set")
        raise ValueError("GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET must be set")

    # Create auth provider
    auth_provider = GitHubProvider(
        client_id=GITHUB_CLIENT_ID,
        client_secret=GITHUB_CLIENT_SECRET,
        base_url=BASE_URL,
    )
    logger.info("GitHubProvider created for OAuth")

    # Create MCP server with auth
    mcp = FastMCP(name="Gmail with Macaroons", auth=auth_provider)
    logger.info("FastMCP instance created: 'Gmail with Macaroons'")

    # Add the new macaroon middleware
    mcp.add_middleware(MacaroonMiddleware("config/policies.yaml"))
    logger.info("Added MacaroonMiddleware to MCP")
    
    # Set logging level for mcp_macaroon_middleware to DEBUG
    logging.getLogger("mcp_macaroon_middleware").setLevel(logging.DEBUG)

    return mcp

# --- Tool Examples ---

def add_gmail_tools(mcp: FastMCP):
	"""Add Gmail tools to the MCP server."""
	logger.info("Registering Gmail tools on MCP")
	
	@mcp.tool
	def read_emails(sender: str, last_n: int = 1):
		"""Read emails from sender."""
		logger.info("Tool 'read_emails' called with sender=%s, last_n=%d", sender, last_n)
		# Mock response - replace with actual Gmail API call
		import requests
		try:
			response = requests.post("http://127.0.0.1:8000/read-emails", json={
				"sender": sender,
				"last_n": last_n
			})
			logger.debug("Outbound request to http://127.0.0.1:8000/read-emails sent, status=%s", response.status_code)
			response.raise_for_status()
			data = response.json()
			logger.debug("Received response data type: %s", type(data))
			return data
		except Exception as e:
			logger.exception(f"Error reading emails: {e}")
			return [{"error": str(e)}]
	
	@mcp.tool
	async def get_user_profile(ctx: Context):
		"""Get authenticated user profile."""
		logger.info("Tool 'get_user_profile' called")
		token = get_access_token()
		user_id = ctx.fastmcp_context.get_state("user_id")
		logger.debug("get_user_profile: user_id=%s, token_claim_keys=%s", user_id, list(token.claims.keys()))
		
		profile = {
			"user_id": user_id,
			"login": token.claims.get("login"),
			"name": token.claims.get("name"),
			"email": token.claims.get("email")
		}
		logger.info("Returning user profile for user_id=%s", user_id)
		return profile

if __name__ == "__main__":
    try:
        logger.info("Starting main - creating server and registering tools")
        mcp = create_mcp_server_with_macaroon_auth()
        add_gmail_tools(mcp)

        logger.info("Starting MCP server with Macaroon authentication...")
        logger.info("GitHub OAuth callback: http://localhost:9001/auth/callback")
        mcp.run(transport="http", port=9001, log_level="debug")
    except Exception as e:
        logger.exception("Failed to start MCP server: %s", e)
        raise