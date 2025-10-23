import json
import sys

try:
    import yaml
except ImportError:
    print("PyYAML library not found. Please install it using: pip install PyYAML")
    sys.exit(1)

def parse_openapi_to_json(file_path):
    """
    Parses an OpenAPI (YAML or JSON) file and outputs a JSON array of endpoint information.

    Args:
        file_path (str): The path to the OpenAPI file.
    """
    try:
        with open(file_path, 'r') as f:
            if file_path.endswith('.json'):
                spec = json.load(f)
            elif file_path.endswith('.yml') or file_path.endswith('.yaml'):
                spec = yaml.safe_load(f)
            else:
                print(f"Error: Unsupported file extension for {file_path}. Please use .json, .yml, or .yaml.")
                return

        if 'paths' not in spec:
            print("Error: 'paths' not found in the OpenAPI specification.")
            return

        output_data = []
        for path, path_item in spec.get('paths', {}).items():
            for method, operation in path_item.items():
                function_name = operation.get('operationId')
                if not function_name:
                    function_name = f"{method.upper()} {path}"

                description = operation.get('description') or operation.get('summary') or "No description available."

                security_scopes = []
                for security_req in operation.get('security', []):
                    for key, scopes in security_req.items():
                        security_scopes.extend(scopes)

                endpoint_info = {
                    "function_name": function_name,
                    "description": description,
                    "path": path,
                    "method": method,
                    "parameters": [],
                    "request_body": None,
                    "security_scopes": security_scopes
                }

                parameters = operation.get('parameters', [])
                for param in parameters:
                    endpoint_info["parameters"].append({
                        "name": param.get('name'),
                        "in": param.get('in'),
                        "description": param.get('description') or "No description.",
                        "required": param.get('required', False),
                        "schema": param.get('schema')
                    })

                request_body = operation.get('requestBody', {})
                if request_body:
                    endpoint_info["request_body"] = {
                        "description": request_body.get('description') or "No description.",
                        "content": {}
                    }
                    if 'content' in request_body:
                        for media_type, media_type_obj in request_body['content'].items():
                            endpoint_info["request_body"]["content"][media_type] = {
                                "schema": media_type_obj.get('schema')
                            }

                output_data.append(endpoint_info)

        print(json.dumps(output_data, indent=2))

    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python parse_openapi_to_json.py <path_to_openapi_file>")
        sys.exit(1)

    file_path = sys.argv[1]
    parse_openapi_to_json(file_path)