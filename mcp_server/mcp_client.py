import os
import json
import asyncio
from typing import Any, Dict, List, Optional

# Official libraries
import google.generativeai as genai
from fastmcp import Client # Official FastMCP Client
from fastmcp.tools.tool import ToolResult

# Configure Gemini API
# NOTE: Ensure GEMINI_API_KEY is set in your environment
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY") 
if not GEMINI_API_KEY:
    print("❌ ERROR: GEMINI_API_KEY not set in environment variables")
    exit(1)
genai.configure(api_key=GEMINI_API_KEY)

class FastMCPGeminiClient:
    """
    Integrates the official fastmcp.Client with the Gemini API 
    for function calling.
    """
    def __init__(self, mcp_server_url: str = "http://127.0.0.1:8001/mcp"):
        # The FastMCP Client automatically manages transport and HTTP connections
        self.mcp_client = Client(mcp_server_url)
        self.model = genai.GenerativeModel('gemini-2.5-pro')
        self.chat = None
        self.gemini_tools = []
        
    def convert_mcp_tools_to_gemini_format(self, tools: List[Dict]) -> List[Dict]:
        """Converts raw MCP tool definitions to Gemini function calling format."""
        gemini_tools = []
        for tool in tools:
            gemini_tool = {
                "name": tool["name"],
                "description": tool.get("description", ""),
                "parameters": {
                    "type": "object",
                    "properties": tool.get("inputSchema", {}).get("properties", {}),
                    "required": tool.get("inputSchema", {}).get("required", [])
                }
            }
            # Encapsulate the function declaration within the required 'tools' list
            gemini_tools.append({"function_declarations": [gemini_tool]})
        return gemini_tools
    
    def extract_text_from_tool_result(self, tool_result: List[ToolResult]) -> str:
        """Extracts and concatenates text content from an MCP ToolResult list."""
        result_text = ""
        for item in tool_result:
            # ToolResult parts are dictionaries containing 'type' and 'text' keys
            if item.get("type") == "text":
                result_text += item.get("text", "")
        return result_text

    async def process_tool_calls(self, response) -> Any:
        """Manually executes function calls requested by Gemini."""
        max_iterations = 5
        iteration = 0
        
        while iteration < max_iterations:
            # Check for a function call in the response
            parts = response.candidates[0].content.parts if response.candidates else None
            if not parts or not parts[0].function_call:
                break
            
            function_call = parts[0].function_call
            tool_name = function_call.name
            tool_args = dict(function_call.args) 
            
            print(f"\n🔧 Calling tool: {tool_name}")
            print(f"   Arguments: {json.dumps(tool_args, indent=2)}")
            
            # Use the official fastmcp.Client to call the tool
            try:
                tool_result_parts = await self.mcp_client.call_tool(
                    name=tool_name, 
                    arguments=tool_args
                )
                result_text = self.extract_text_from_tool_result(tool_result_parts)
                status = "Success"
            except Exception as e:
                result_text = f"Error calling tool {tool_name}: {e}"
                status = "Failure"

            display_result = result_text[:200] + ("..." if len(result_text) > 200 else "")
            print(f"   Result ({status}): {display_result}")
            
            # Send function response back to Gemini for the next turn
            response = await asyncio.to_thread(
                self.chat.send_message,
                genai.protos.Content(
                    parts=[genai.protos.Part(
                        function_response=genai.protos.FunctionResponse(
                            name=tool_name,
                            # Simple response structure expected by Gemini
                            response={"result": result_text} 
                        )
                    )]
                )
            )
            
            iteration += 1
        
        return response

    async def chat_loop(self):
        """Main interactive chat loop."""
        print("\n" + "="*60)
        print("FastMCP + Gemini Client (using fastmcp.Client)")
        print("="*60)
        print("Type 'quit' or 'exit' to end the conversation\n")
        
        # 1. Connect and fetch tools using the client's context manager
        async with self.mcp_client:
            print(f"✓ Connected to MCP server at {self.mcp_client.url}")
            
            # Fetch and convert tools
            mcp_tools = await self.mcp_client.list_tools()
            self.gemini_tools = self.convert_mcp_tools_to_gemini_format(mcp_tools)
            
            print(f"✓ Available tools ({len(mcp_tools)}) converted for Gemini.")
            
            # 2. Initialize chat
            self.chat = self.model.start_chat(
                history=[],
                enable_automatic_function_calling=False 
            )

            # 3. Start chat loop
            while True:
                try:
                    user_input = input("You: ").strip()
                    
                    if user_input.lower() in ['quit', 'exit']:
                        print("Goodbye!")
                        break
                    
                    if not user_input:
                        continue
                    
                    # Send message to Gemini with tools config
                    response = await asyncio.to_thread(
                        self.chat.send_message,
                        user_input,
                        config={"tools": self.gemini_tools} if self.gemini_tools else None
                    )
                    
                    # Process any function calls
                    response = await self.process_tool_calls(response)
                    
                    # Print Gemini's final response
                    print(f"\nGemini: {response.text}\n")
                    
                except KeyboardInterrupt:
                    print("\n\nGoodbye!")
                    break
                except Exception as e:
                    print(f"\n✗ Error in chat loop: {e}\n")

async def main():
    server_url = os.environ.get("MCP_SERVER_URL", "http://127.0.0.1:8001")
    client = FastMCPGeminiClient(mcp_server_url=server_url)
    
    await client.chat_loop()

if __name__ == "__main__":
    asyncio.run(main())