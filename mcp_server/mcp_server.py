import logging
from fastmcp import FastMCP
from mcp.types import TextContent
from fastmcp.server.middleware import Middleware
from fastmcp.server.elicitation import (
    AcceptedElicitation
)
from fastmcp.tools.tool import ToolResult
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import requests
import json
from pymacaroons import Macaroon, Verifier

# --- Configuration for logging ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Macaroon Setup (from original code) ---
secret_key = "this_is_a_secret_key"

def create_macaroon():
    identifier = "gmail_macaroon"
    # Macaroon location is typically the service it controls
    macaroon = Macaroon(location="gmail_service", identifier=identifier, key=secret_key)
    # Add a base service caveat
    macaroon.add_first_party_caveat("service = gmail")
    logger.info("Created a new base macaroon.")
    return macaroon.serialize()
    
def add_caveat(macaroon: Macaroon, field: str):
    # Field-level permission caveat
    caveat_str = "allowed_field = {}".format(field)
    macaroon.add_first_party_caveat(caveat_str)
    logger.info(f"Added caveat: {caveat_str}")
    return macaroon

def add_caveat_allowed_functions(macaroon: Macaroon, function_name: str):
    caveat_str = "allowed_function = {}".format(function_name)
    macaroon.add_first_party_caveat(caveat_str)
    logger.info(f"Added caveat: {caveat_str}")
    return macaroon

def verify_macaroon(macaroon: Macaroon, secret_key: str) -> bool:
    try:
        v = Verifier()
        # The base requirement for the service
        v.satisfy_exact("service = gmail") 
        v.verify(macaroon, secret_key)
        logger.info("Macaroon base verification successful.")
        return True
    except Exception as e:
        logger.error(f"Macaroon base verification failed: {e}")
        return False

def get_allowed_fields(macaroon: Macaroon) -> set:
    """Extracts the set of allowed fields from the macaroon caveats."""
    allowed_fields = set()
    for caveat in macaroon.caveats:
        # Correctly check and extract the field name
        if caveat.caveat_id.startswith("allowed_field = "):
            # Split by " = " and take the second part (the field name)
            field_name = caveat.caveat_id.split(" = ", 1)[1].strip()
            if field_name:
                allowed_fields.add(field_name)
    return allowed_fields

def get_allowed_functions(macaroon: Macaroon) -> set:
    """Extracts the set of allowed functions from the macaroon caveats."""
    allowed_functions = set()
    for caveat in macaroon.caveats:
        if caveat.caveat_id.startswith("allowed_function = "):
            function_name = caveat.caveat_id.split(" = ", 1)[1].strip()
            if function_name:
                allowed_functions.add(function_name)
    return allowed_functions

# --- Macaroon Middleware with Logging ---
class MacaroonMiddleware(Middleware):
    async def on_call_tool(self, context, call_next):
        logger.info(f"--- Macaroon Middleware started for tool call ---")

        # 1. Initialization and Verification
        macaroon_serialized = context.fastmcp_context.get_state("macaroon")
        if not macaroon_serialized:
            # Create a base macaroon if one doesn't exist
            logger.info("No macaroon found in state. Creating a new one.")
            macaroon_serialized = create_macaroon()
            context.fastmcp_context.set_state("macaroon", macaroon_serialized)
        
        try:
            macaroon = Macaroon.deserialize(macaroon_serialized)
        except Exception as e:
            logger.error(f"Failed to deserialize macaroon: {e}")
            raise Exception("Invalid serialized macaroon format.")
        
        # Verify the base macaroon's integrity and service scope
        if not verify_macaroon(macaroon, secret_key):
            raise Exception("Invalid macaroon or missing 'service = gmail' caveat.")
        
        # 2. Execute the tool call
        logger.info("Executing the next tool call...")
        result = await call_next(context)
        logger.info("Tool call execution complete.")
        
        # Ensure the result content is handled correctly
        tool_result = result.content
        tool_result_dict: List[Dict[str, Any]] = []
        try:
            if isinstance(tool_result, List) and tool_result and isinstance(tool_result[0], TextContent):
                tool_result_dict = json.loads(tool_result[0].text)
                if not isinstance(tool_result_dict, List):
                    # Handle case where json.loads results in a single dict, wrap it in a list
                    tool_result_dict = [tool_result_dict]
            else:
                logger.error(f"Unexpected tool result format: {type(tool_result)}")
                raise Exception("Unexpected tool result format.")
        except (json.JSONDecodeError, IndexError) as e:
            logger.error(f"Failed to process tool result JSON: {e}")
            raise Exception("Failed to process tool result content.")

        logger.info(f"Tool response contains {len(tool_result_dict)} item(s).")
        if tool_result_dict:
            logger.debug(f"Tool result fields: {list(tool_result_dict[0].keys())}")
                
        
        # 3. Elicitation and Caveat Update
        
        # Get the fields already permitted
        macaroon_current = Macaroon.deserialize(context.fastmcp_context.get_state("macaroon"))
        allowed_fields = get_allowed_fields(macaroon_current)
        logger.info(f"Current allowed fields: {allowed_fields}")
        
        new_field_permitted = False
        
        if tool_result_dict:
            # Elicit new caveats for any fields in the response not already allowed
            for field in tool_result_dict[0].keys():
                if field not in allowed_fields:
                    logger.warning(f"Field '{field}' is not allowed. Starting elicitation.")
                    # Ask the user for permission for the new field
                    resp = await context.fastmcp_context.elicit(f"Give permission to access field: **{field}**?", response_type=bool)

                    match resp:
                        case AcceptedElicitation():
                            # If accepted, add the new field permission to the macaroon
                            macaroon_current = add_caveat(macaroon_current, field)
                            new_field_permitted = True
                            allowed_fields.add(field) # Add to the current set for immediate filtering
                            logger.info(f"Permission granted for field: {field}")
                        case _:
                            # If rejected or timeout, the field remains disallowed
                            logger.info(f"Permission NOT granted for field: {field}")
                            pass
        
        # If new permissions were granted, update the state
        if new_field_permitted:
            context.fastmcp_context.set_state("macaroon", macaroon_current.serialize())
            logger.info("Macaroon updated and state saved.")

        # 4. Filter the Response
        # Re-fetch/Re-deserialize in case the state was just updated
        macaroon_final = Macaroon.deserialize(context.fastmcp_context.get_state("macaroon"))
        allowed_fields_final = get_allowed_fields(macaroon_final)
        logger.info(f"Final allowed fields for filtering: {allowed_fields_final}")
        
        # Filter the response based on the now-updated set of allowed fields
        filtered_result = [{k: v for k, v in email_dict.items() if k in allowed_fields_final} for email_dict in tool_result_dict]
        
        logger.info(f"Result filtered. {len(filtered_result)} item(s) to be returned.")
        if filtered_result and tool_result_dict:
            # Log the number of fields before and after filtering on the first item
            fields_before = len(tool_result_dict[0].keys())
            fields_after = len(filtered_result[0].keys())
            logger.info(f"First item: {fields_before} fields before filtering, {fields_after} fields after.")

        if isinstance(result.content, List) and result.content and isinstance(result.content[0], TextContent):
            # Update the text content with the filtered result
            result.content[0].text = json.dumps(filtered_result)
            logger.info("Result content updated with filtered JSON.")
            return result
        
        logger.error("Final result content was not in the expected TextContent list format.")
        return result


mcp = FastMCP("gmail")

# Add the middleware with logging
mcp.add_middleware(MacaroonMiddleware())

class Email(BaseModel):
    to: str
    subject: str
    body: str

@mcp.tool
def send_email(email: Email):
    """
    Sends an email by making a POST request to the gmail_fastapi_server.
    """
    logger.info(f"Attempting to send email to: {email.to}")
    # Assuming this endpoint returns a dict like: 
    # {"status": "success", "message_id": "..."}
    try:
        response = requests.post("http://127.0.0.1:8000/send-email", json=email.dict())
        response.raise_for_status() # Raise an exception for bad status codes
        logger.info("Email sent successfully (simulated/mocked endpoint call).")
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Error sending email: {e}")
        return {"status": "error", "detail": str(e)}

@mcp.tool
def read_emails(sender: str, last_n: int = 1, time_limit_days: Optional[int] = None):
    """
    Reads emails by making a POST request to the gmail_fastapi_server.
    """
    logger.info(f"Attempting to read {last_n} emails from sender: {sender}")
    # Assuming this endpoint returns a list of email dicts, e.g.:
    # [{"subject": "...", "body": "...", "timestamp": "...", "sender": "..."}]
    try:
        response = requests.post("http://127.0.0.1:8000/read-emails", json={
            "sender": sender,
            "last_n": last_n,
            "time_limit_days": time_limit_days
        })
        response.raise_for_status()
        logger.info("Emails read successfully (simulated/mocked endpoint call).")
        # We expect the inner content of the response to be a list of dicts
        result = response.json()
        return result
    except requests.exceptions.RequestException as e:
        logger.error(f"Error reading emails: {e}")
        return [{"status": "error", "detail": str(e)}]


if __name__ == "__main__":
    logger.info("Starting FastMCP server with MacaroonMiddleware...")
    mcp.run(transport="http", host="0.0.0.0", port=8001)