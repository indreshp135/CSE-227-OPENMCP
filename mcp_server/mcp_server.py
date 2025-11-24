import logging
import json
from multiprocessing import context
from typing import Dict, Optional, Set, Any, List
from fastmcp import FastMCP, Context
from fastmcp.server.middleware import Middleware
from fastmcp.server.auth.providers.github import GitHubProvider
from fastmcp.server.dependencies import get_access_token
from fastmcp.server.elicitation import AcceptedElicitation
from mcp.types import TextContent
from pymacaroons import Macaroon, Verifier
import os
import re
import dotenv

dotenv.load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
# --- Macaroon Configuration ---
SECRET_KEY = os.environ.get("MACAROON_SECRET_KEY", "this_is_a_secret_key")
logger.debug("Macaroon secret key loaded (hidden).")
class MacaroonAuthMiddleware(Middleware):
	"""
	Middleware that maps OAuth tokens to Macaroons and handles field-level permissions.
	"""
	
	def __init__(self):
		logger.info("Initializing MacaroonAuthMiddleware")
		self.token_to_macaroon: Dict[str, str] = {}  # In-memory token -> macaroon mapping
		logger.debug("Initialized in-memory token_to_macaroon mapping (empty).")
	
	def create_base_macaroon(self, user_id: str, service: str = "gmail") -> str:
		"""Create a base macaroon for a user and service."""
		logger.info(f"Creating base macaroon for user_id={user_id}, service={service}")
		identifier = f"{service}_macaroon_{user_id}"
		macaroon = Macaroon(
			location=f"{service}_service", 
			identifier=identifier, 
			key=SECRET_KEY
		)
		# Add base service caveat
		caveat_service = f"service = {service}"
		caveat_user = f"user = {user_id}"
		macaroon.add_first_party_caveat(caveat_service)
		macaroon.add_first_party_caveat(caveat_user)
		logger.debug(f"Added base caveats: [{caveat_service}, {caveat_user}] to macaroon id={identifier}")
		
		# Add initial attempts caveat
		initial_attempts = 5
		caveat_attempts = f"attempts_remaining = {initial_attempts}"
		macaroon.add_first_party_caveat(caveat_attempts)
		logger.debug(f"Added attempts caveat: {caveat_attempts} to macaroon id={identifier}")

		logger.info(f"Created base macaroon for user: {user_id}, service: {service}")
		return macaroon.serialize()
	
	def get_or_create_macaroon(self, token_id: str, user_id: str) -> str:
		"""Get existing macaroon for token or create new one."""
		logger.info(f"Retrieving or creating macaroon for token_id={token_id}, user_id={user_id}")
		if token_id in self.token_to_macaroon:
			logger.info(f"Retrieved existing macaroon for token: {token_id}")
			return self.token_to_macaroon[token_id]
		
		# Create new macaroon for this token
		macaroon_serialized = self.create_base_macaroon(user_id)
		self.token_to_macaroon[token_id] = macaroon_serialized
		logger.info(f"Created and cached new macaroon for token: {token_id}")
		logger.debug(f"token_to_macaroon size: {len(self.token_to_macaroon)}")
		return macaroon_serialized
	
	def get_allowed_fields(self, macaroon: Macaroon) -> Set[str]:
		"""Extract allowed fields from macaroon caveats."""
		allowed_fields = set()
		logger.debug("Extracting allowed fields from macaroon caveats")
		for caveat in macaroon.caveats:
			logger.debug(f"Inspecting caveat: {caveat.caveat_id}")
			if caveat.caveat_id.startswith("allowed_field = "):
				field_name = caveat.caveat_id.split(" = ", 1)[1].strip()
				if field_name:
					allowed_fields.add(field_name)
					logger.debug(f"Found allowed field caveat: {field_name}")
		logger.info(f"Allowed fields extracted: {allowed_fields}")
		return allowed_fields
	
	def add_field_caveat(self, macaroon: Macaroon, field: str) -> Macaroon:
		"""Add field permission caveat to macaroon."""
		logger.info(f"Adding field caveat for field='{field}' to macaroon id={macaroon.identifier}")
		caveat_str = f"allowed_field = {field}"
		macaroon.add_first_party_caveat(caveat_str)
		logger.debug(f"Added caveat string: {caveat_str}")
		return macaroon
	def add_caveat_allowed_functions(self, macaroon: Macaroon, function_name: str):
		caveat_str = "allowed_function = {}".format(function_name)
		macaroon.add_first_party_caveat(caveat_str)
		logger.info(f"Added caveat: {caveat_str}")
		return macaroon
	
	def get_allowed_functions(self, macaroon: Macaroon) -> set:
		"""Extracts the set of allowed functions from the macaroon caveats."""
		allowed_functions = set()
		for caveat in macaroon.caveats:
			logger.info("caveat %s", caveat)
			if caveat.caveat_id.startswith("allowed_function = "):
				function_name = caveat.caveat_id.split(" = ", 1)[1].strip()
				if function_name:
					allowed_functions.add(function_name)
		logger.info("Allowed functions: %s", allowed_functions)
		return allowed_functions
	
	def get_attempts_remaining(self, macaroon: Macaroon) -> int:
		"""Return the most recent attempts_remaining value from caveats."""
		attempts = None
		for cav in macaroon.caveats:
			if cav.caveat_id.startswith("attempts_remaining = "):
				try:
					attempts = int(cav.caveat_id.split("=", 1)[1].strip())
				except ValueError:
					pass
		return attempts

	def decrement_attempts(self, macaroon: Macaroon) -> Macaroon:
		"""Decrease attempts_remaining by 1 and add a new caveat."""
		attempts = self.get_attempts_remaining(macaroon)

		if attempts is None:
			raise Exception("Macaroon missing attempts_remaining caveat")

		new_attempts = attempts - 1
		caveat = f"attempts_remaining = {new_attempts}"

		macaroon.add_first_party_caveat(caveat)
		logger.info(f"Attempts decremented: {attempts} -> {new_attempts}")

		if new_attempts <= 0:
			raise Exception("Maximum number of attempts reached")

		return macaroon

	def verify_macaroon(self, macaroon: Macaroon, secret_key: str) -> bool:
		"""Verify macaroon integrity and base requirements."""
		logger.debug("Verifying macaroon integrity and caveats")
		try:
			v = Verifier()
			v.satisfy_exact("service = gmail")
			
			# Satisfy all caveats dynamically
			for caveat in macaroon.caveats:
				caveat_id = caveat.caveat_id
				if caveat_id.startswith("user = "):
					v.satisfy_exact(caveat_id)
				elif caveat_id.startswith("allowed_field = "):
					v.satisfy_exact(caveat_id)
				elif caveat_id.startswith("allowed_function = "):
					v.satisfy_exact(caveat_id)
				elif caveat_id.startswith("attempts_remaining = "):
					v.satisfy_exact(caveat_id)
			
			v.verify(macaroon, secret_key)
			logger.info("Macaroon verification successful")
			return True
		except Exception as e:
			logger.exception(f"Macaroon verification failed: {e}")
			return False
	
	async def on_call_tool(self, context, call_next):
		"""Main middleware logic for handling tool calls with macaroon authorization."""
		logger.info("=== MacaroonAuthMiddleware started ===")
		
		# 1. Get the authentication token
		try:
			token = get_access_token()
			user_id = token.claims.get("login", "unknown_user")
			token_id = f"{user_id}_{hash(str(token.claims))}"  # Create stable token ID
			logger.info(f"Processing request for user: {user_id}")
			logger.debug(f"Token id: {token_id}; token claim keys: {list(token.claims.keys())}")
		except Exception as e:
			logger.exception(f"Failed to get access token: {e}")
			raise Exception("Authentication required")
		
		# 2. Get or create macaroon for this token
		macaroon_serialized = self.get_or_create_macaroon(token_id, user_id)
		
		# Store macaroon in context state for this request
		context.fastmcp_context.set_state("macaroon", macaroon_serialized)
		context.fastmcp_context.set_state("user_id", user_id)
		context.fastmcp_context.set_state("token_id", token_id)
		logger.debug("Context state set: macaroon (serialized length=%d), user_id=%s, token_id=%s",
					 len(macaroon_serialized), user_id, token_id)
		
		# 3. Verify macaroon
		try:
			macaroon = Macaroon.deserialize(macaroon_serialized)
			logger.debug("Deserialized macaroon successfully")
		except Exception as e:
			logger.exception(f"Failed to deserialize macaroon: {e}")
			raise Exception("Invalid macaroon format")
		
		if not self.verify_macaroon(macaroon, SECRET_KEY):
			logger.error("Macaroon verification failed - rejecting request")
			raise Exception("Invalid macaroon or missing required caveats")
		
		# 3.5: Decrement attempts
		try:
			macaroon = self.decrement_attempts(macaroon)
			updated_serialized = macaroon.serialize()
			self.token_to_macaroon[token_id] = updated_serialized
			context.fastmcp_context.set_state("macaroon", updated_serialized)
		except Exception as e:
			raise Exception("No attempts remaining") from e
		
		attempts_remaining = self.get_attempts_remaining(macaroon)

		# Notify user of remaining attempts
		try:
			await context.fastmcp_context.elicit(
				f"You have **{attempts_remaining} attempts** remaining.",
				response_type=None
			)
		except Exception as e:
			logger.warning(f"Failed to send attempt notification: {e}")

		allowed_functions = self.get_allowed_functions(macaroon)
		# Safe extractor for tool name from various MiddlewareContext shapes
		def _extract_tool_name(ctx) -> Optional[str]:
			msg = getattr(ctx, "message", None)
			if msg is None:
				return None
			# Common: message has a .name attribute
			if hasattr(msg, "name"):
				return getattr(msg, "name")
			# Nested message.message.name
			inner = getattr(msg, "message", None)
			if inner and hasattr(inner, "name"):
				return getattr(inner, "name")
			# dict-like
			try:
				if isinstance(msg, dict):
					return msg.get("name") or (msg.get("message") and msg["message"].get("name"))
			except Exception:
				pass
			# Fallback: regex on repr
			m = re.search(r"name=['\"]([^'\"]+)['\"]", repr(msg))
			if m:
				return m.group(1)
			return None
		tool_name = _extract_tool_name(context)
		logger.info("Tool being called: %s", tool_name)
  
  
		# If we couldn't extract the name, log and skip the allowed-functions enforcement
		if tool_name is None:
			logger.warning("Could not extract tool name from context; skipping allowed-functions check.")
		else:
			logger.info(f"Allowed functions in macaroon: {allowed_functions}")
   
			if tool_name not in allowed_functions:
				# Request permission for function
				permission_granted = await self._handle_function_permissions(context, tool_name, token_id)
				if not permission_granted:
					logger.error(f"Permission denied for function: {tool_name}")
					raise Exception(f"Permission denied for function: {tool_name}")
		
		# 4. Execute tool call
		logger.info("Executing tool call...")
		try:
			result = await call_next(context)
			logger.info("Tool call execution complete")
			logger.debug("Tool returned result object of type: %s", type(result))
		except Exception as e:
			logger.exception("Exception while executing tool call: %s", e)
			raise
		
		# 5. Process and filter response based on macaroon permissions
		try:
			tool_result_dict = self._extract_tool_result(result)
			logger.info(f"Tool response contains {len(tool_result_dict)} item(s)")
			
			if tool_result_dict:
				# Handle permission elicitation and filtering
				filtered_result = await self._handle_permissions_and_filter(
					context, tool_result_dict, token_id
				)
				
				# Update result with filtered content
				self._update_result_content(result, filtered_result)
				
		except Exception as e:
			logger.exception(f"Error processing tool result: {e}")
			# Return original result if processing fails
		
		logger.info("=== MacaroonAuthMiddleware complete ===")
		return result
	
	def _extract_tool_result(self, result) -> List[Dict[str, Any]]:
		"""Extract tool result as list of dictionaries."""
		logger.debug("Extracting tool result from result.content")
		tool_result = result.content
		
		logger.debug("Result content type: %s", type(tool_result))
		if isinstance(tool_result, list) and tool_result and isinstance(tool_result[0], TextContent):
			try:
				tool_result_dict = json.loads(tool_result[0].text)
			except json.JSONDecodeError as e:
				logger.error(f"Failed to JSON-decode TextContent.text: {e}")
				raise
			if isinstance(tool_result_dict, dict):
				tool_result_dict = [tool_result_dict]
		# Case B: framework returned a raw list of dicts (already-parsed JSON)
		elif isinstance(tool_result, list) and tool_result and isinstance(tool_result[0], dict):
			tool_result_dict = tool_result
		# Case C: framework returned a single dict
		elif isinstance(tool_result, dict):
			tool_result_dict = [tool_result]
		else:
			logger.warning("Unexpected tool result format; expected List[TextContent]")
			return []

		return tool_result_dict
	
	async def _handle_permissions_and_filter(self, context, tool_result_dict: List[Dict], token_id: str) -> List[Dict]:
		"""Handle permission elicitation and filter results."""
		logger.info("Handling permissions and filtering results")
		# Get current macaroon and allowed fields
		macaroon_serialized = context.fastmcp_context.get_state("macaroon")
		logger.debug("Loaded macaroon from context state (serialized length=%d)", len(macaroon_serialized))
		macaroon_current = Macaroon.deserialize(macaroon_serialized)
		allowed_fields = self.get_allowed_fields(macaroon_current)
		logger.info(f"Current allowed fields: {allowed_fields}")
		
		new_permissions_granted = False
		
		if tool_result_dict:
			# Check each field in the first result item
			for field in tool_result_dict[0].keys():
				logger.debug(f"Evaluating field '{field}' for permission")
				if field not in allowed_fields:
					logger.warning(f"Field '{field}' not allowed - requesting permission")
					
					# Elicit permission from user
					try:
						resp = await context.fastmcp_context.elicit(
							f"Grant access to field: **{field}**?", 
							response_type=bool
						)
						logger.debug(f"Elicitation response received for field '{field}': {type(resp)}")
					except Exception as e:
						logger.exception(f"Elicitation failed for field '{field}': {e}")
						resp = None
					
					if isinstance(resp, AcceptedElicitation):
						# Permission granted - add caveat
						macaroon_current = self.add_field_caveat(macaroon_current, field)
						allowed_fields.add(field)
						new_permissions_granted = True
						logger.info(f"Permission granted for field: {field}")
					else:
						logger.info(f"Permission denied or not granted for field: {field}")
		# Update stored macaroon if new permissions were granted
		if new_permissions_granted:
			updated_macaroon_serialized = macaroon_current.serialize()
			self.token_to_macaroon[token_id] = updated_macaroon_serialized
			# self.verify_macaroon(self.token_to_macaroon[token_id], SECRET_KEY)  # Verify updated macaroon
			logger.info("Macaroon updated with new permissions and cached")
			logger.debug("Updated macaroon serialized length=%d", len(updated_macaroon_serialized))
		
		# Filter results based on final allowed fields
		filtered_result = [
			{k: v for k, v in item.items() if k in allowed_fields}
			for item in tool_result_dict
		]
		
		logger.info(f"Filtered result items count: {len(filtered_result)}")
		return filtered_result

	# add function for eliciting allowed functions
	async def _handle_function_permissions(self, context, tool_name: str, token_id: str) -> bool:
		"""Elicit permission for a function and persist macaroon if granted."""
		logger.info(f"Handling function permission for tool: {tool_name}")

		# Load current macaroon from context
		macaroon_serialized = context.fastmcp_context.get_state("macaroon")
		logger.debug("Loaded macaroon from context state (serialized length=%d)", len(macaroon_serialized))
		macaroon_current = Macaroon.deserialize(macaroon_serialized)

		# Check if already allowed
		allowed_functions = self.get_allowed_functions(macaroon_current)
		if tool_name in allowed_functions:
			logger.info(f"Function '{tool_name}' is already allowed.")
			return True

		# Request permission from user
		logger.warning(f"Function '{tool_name}' not allowed - requesting permission")
		try:
			resp = await context.fastmcp_context.elicit(
				f"Grant access to function: **{tool_name}**?", 
				response_type=bool
			)
			logger.debug(f"Elicitation response received for function '{tool_name}': {type(resp)}")
		except Exception as e:
			logger.exception(f"Elicitation failed for function '{tool_name}': {e}")
			resp = None

		if isinstance(resp, AcceptedElicitation):
			# Permission granted: add caveat and persist macaroon
			macaroon_current = self.add_caveat_allowed_functions(macaroon_current, tool_name)
			updated_macaroon_serialized = macaroon_current.serialize()
			self.token_to_macaroon[token_id] = updated_macaroon_serialized
			context.fastmcp_context.set_state("macaroon", updated_macaroon_serialized)
			logger.info(f"Permission granted for function: {tool_name} and macaroon updated")
			return True
		else:
			logger.info(f"Permission denied or not granted for function: {tool_name}")
			return False

	
	def _update_result_content(self, result, filtered_result: List[Dict]):
		"""Update the result content with filtered data."""
		logger.debug("Updating result content with filtered data")
		if (isinstance(result.content, List) and 
			result.content and 
			isinstance(result.content[0], TextContent)):
			result.content[0].text = json.dumps(filtered_result)
			logger.info("Result content updated with filtered data")
			logger.debug("Updated result.content[0].text length=%d", len(result.content[0].text))
		else:
			logger.warning("Could not update result content - unexpected format")
   
# --- Example Usage ---
def create_mcp_server_with_macaroon_auth():
	"""Create MCP server with GitHub auth and macaroon middleware."""
	logger.info("Creating MCP server with Macaroon authentication")
	
	# Load GitHub OAuth credentials
	GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID")
	GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET")
	BASE_URL = os.environ.get("BASE_URL", "http://localhost:9000")
	
	logger.debug("GITHUB_CLIENT_ID present: %s, BASE_URL=%s", bool(GITHUB_CLIENT_ID), BASE_URL)
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
	
	# Add macaroon middleware
	mcp.add_middleware(MacaroonAuthMiddleware())
	logger.info("Added MacaroonAuthMiddleware to MCP")
	
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
	
if __name__ == "__main__":
	# Create server with macaroon auth
	try:
		logger.info("Starting main - creating server and registering tools")
		mcp = create_mcp_server_with_macaroon_auth()
		add_gmail_tools(mcp)
		
		logger.info("Starting MCP server with Macaroon authentication...")
		logger.info("GitHub OAuth callback: http://localhost:9000/auth/callback")
		mcp.run(transport="http", port=9000, log_level="debug")
	except Exception as e:
		logger.exception("Failed to start MCP server: %s", e)
		raise