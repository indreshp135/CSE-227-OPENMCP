import logging
from typing import Any, Dict, List
from mcp.types import TextContent
import json
from fastmcp.tools.tool import ToolResult

logger = logging.getLogger(__name__)

def extract_content_to_dicts(result: ToolResult) -> List[Dict[str, Any]]:
    """
    Extracts content from a ToolResult, attempting to parse TextContent objects
    into a list of dictionaries. Handles various FastMCP result formats.
    """
    logger.debug("Attempting to extract content from ToolResult.")
    
    if not result or not result.content:
        logger.debug("ToolResult or its content is empty.")
        return []

    tool_result_content = result.content
    
    # Case 1: result.content is a list where the first item is TextContent
    if isinstance(tool_result_content, list) and tool_result_content and \
       isinstance(tool_result_content[0], TextContent):
        try:
            # Assume TextContent.text holds JSON string
            if tool_result_content[0].text:
                parsed_data = json.loads(tool_result_content[0].text)
                if isinstance(parsed_data, dict):
                    return [parsed_data]
                elif isinstance(parsed_data, list):
                    return parsed_data
            logger.warning("TextContent.text was empty or not valid JSON.")
            return []
        except json.JSONDecodeError as e:
            logger.error(f"Failed to JSON-decode TextContent.text: {e}", exc_info=True)
            return []
    
    # Case 2: result.content is a list of dictionaries (already parsed)
    elif isinstance(tool_result_content, list) and tool_result_content and \
         isinstance(tool_result_content[0], dict):
        logger.debug("Content is already a list of dictionaries.")
        return tool_result_content
    
    # Case 3: result.content is a single dictionary
    elif isinstance(tool_result_content, dict):
        logger.debug("Content is a single dictionary.")
        return [tool_result_content]
    
    logger.warning(f"Unexpected tool result content format: {type(tool_result_content)}. Expected List[TextContent], List[dict], or dict.")
    return []

def update_result_with_dicts(result, data_to_write: List[Dict[str, Any]]):
    """
    Updates the content of a ToolResult with a list of dictionaries.
    It serializes the dictionaries to JSON and wraps them in a TextContent object.
    """
    logger.debug("Attempting to update ToolResult content with new dictionaries.")
    
    if not result:
        logger.warning("Cannot update an empty ToolResult.")
        return

    # Serialize the list of dictionaries back into a JSON string
    updated_json_str = json.dumps(data_to_write)
    
    # Create a new TextContent object
    new_content_object = TextContent(type="text", text=updated_json_str)
    
    # Update result.content. If it was originally a list of TextContent,
    # replace the first element; otherwise, make it a list containing the new TextContent.
    if isinstance(result.content, list) and result.content and \
       isinstance(result.content[0], TextContent):
        result.content[0] = new_content_object
        logger.debug("Updated existing TextContent in result.content.")
    else:
        result.content = [new_content_object]
        logger.debug("Replaced or set result.content with new TextContent.")

