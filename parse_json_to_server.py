import json

def parse_json_to_server(json_path):
    
    output = """
import requests
from fastmcp import FastMCP
from typing import Any, List, Dict, Union, Optional

mcp = FastMCP()
    """
    
    with open(json_path, 'r') as f:
        # first lets print functions
        data = json.load(f)

    for f in data[:5]:
        name, desc, params, path, method = f['function_name'], f['description'], f['parameters'], f['path'], f['method']
        
        # get params and their types
        param_strs = []
        for p in params:
            try:
                name = p['name']
                type = p['schema']['type']
                if type == 'integer':
                    type = 'Int'
                elif type == 'string':
                    type = 'str'
                param_strs.append(f"{name}: {type}")
            except:
                # handle cases where type is not defined
                param_strs.append(f"{p['name']}: Any")
        param_list = ", ".join(param_strs)

        output += f"""
@mcp.tool
def {name}({param_list}):
    \"\"\"{desc}\"\"\"
    url = "{path}"
    method = "{method}"
    headers = {{'Content-Type': 'application/json'}}
    data = {{k: v for k, v in locals().items() if k != 'data'}}
    response = requests.request(method, url, headers=headers, json=data)
    return response.json()
"""
    return output

if __name__ == "__main__":
    output = parse_json_to_server("./twitter_mcp.json")
        
    with open("generated_server.py", "w") as out_file:
        out_file.write(output)