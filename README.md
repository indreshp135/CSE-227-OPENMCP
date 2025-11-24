# MCP Macaroon Middleware

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PyPI - Version](https://img.shields.io/pypi/v/mcp-macaroon-middleware)](https://pypi.org/project/mcp-macaroon-middleware/)

A production-grade, policy-as-code middleware for `FastMCP` servers that uses macaroons for fine-grained, dynamic, and capability-based authorization.

This middleware allows you to enforce policies on tool calls, both before and after execution, using a simple yet powerful caveat system. Policies are defined in a human-readable YAML file and can be enforced by the built-in policies or by custom Python functions, giving you complete control over your MCP server's security.

## Key Features

- **Policy-as-Code:** Define authorization policies in a simple, human-readable YAML file.
- **Pre & Post Enforcement:** Apply policies before a tool is called (`bf` phase) and/or on the result of the tool call (`af` phase).
- **Extensible:** Easily add new policy enforcement logic using a decorator-based system.
- **Capability-Based Security:** Leverages macaroons to issue time-bound, attenuated credentials.
- **Field-Level Control:** Redact or allow specific fields in tool outputs using the `field_access` policy.
- **Tool Access Control:** Allow or deny access to tools using the `tool_access` policy.
- **Attempt Limiting:** Limit the number of times a tool can be called using the `allow_attempts` policy.
- **Elicitation for Dynamic Permissions:** Dynamically request user consent for specific actions or data access at runtime.
- **Automatic Expiry for Elicited Permissions:** Permissions granted through elicitation can be configured to expire after a specified duration.
- **Configurable Secret Key:** The secret key for signing macaroons can be configured in the `policies.yaml` file.

## Installation

To install the middleware from your local checkout, run the following command from the root of the project:

```bash
pip install .
```

For development, you can install the package in editable mode:

```bash
pip install -e '.[dev]'
```

## Configuration

The middleware is configured through a YAML file (`policies.yaml` by default) that specifies global settings and the initial set of caveats to be added to newly created macaroons.

```yaml
# config/policies.yaml
config:
  # Secret key for signing macaroons. It's recommended to use an environment variable for this.
  secret_key: "this_is_a_very_secret_key"
  # Default expiry for elicited permissions in seconds (e.g., 1 hour)
  elicit_expiry: 3600

policies:
  # Allow calling 'read_emails'
  - "bf:read_emails:tool_access:allow"
  
  # Limit the number of times 'read_emails' can be called
  - "bf:read_emails:allow_attempts:allow:5"

  # After 'read_emails' is called, allow access to the 'subject' field
  - "af:read_emails:field_access:allow:subject"
  
  # Deny access to the 'body' and 'attachments' fields
  - "af:read_emails:field_access:deny:body"
  - "af:read_emails:field_access:deny:attachments"

  # Elicit permission for the 'timestamp' field
  - "af:read_emails:field_access:elicit:timestamp"
```

### Caveat Format

The caveat format is a powerful way to define your policies:

`{phase}:{tool_name}:{policy_name}:{action}:{params...}:time<{expiry}>`

- **`phase`**: `bf` (before) or `af` (after) the tool call.
- **`tool_name`**: The name of the tool to which the policy applies.
- **`policy_name`**: The name of the policy enforcer to call (e.g., `tool_access`, `field_access`, `allow_attempts`).
- **`action`**: The action to take (`allow`, `deny`, `elicit`).
- **`params`**: Optional colon-separated parameters for the policy.
- **`time<{expiry}>`**: An optional expiry timestamp in `YYYYMMDDTHHMMSSZ` format.

## Usage

Here's how to integrate the `MacaroonMiddleware` into your `FastMCP` server.

```python
# examples/server.py
import os
import logging
from fastmcp import FastMCP, Context
from fastmcp.server.auth.providers.github import GitHubProvider
from mcp_macaroon_middleware import MacaroonMiddleware

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_mcp_server():
    """Create an MCP server with Macaroon authentication."""
    GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID")
    GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET")
    BASE_URL = os.environ.get("BASE_URL", "http://localhost:9001")

    if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
        raise ValueError("GitHub credentials must be set.")

    auth_provider = GitHubProvider(
        client_id=GITHUB_CLIENT_ID,
        client_secret=GITHUB_CLIENT_SECRET,
        base_url=BASE_URL,
    )

    mcp = FastMCP(name="My Secure Server", auth=auth_provider)
    mcp.add_middleware(MacaroonMiddleware(config_path="config/policies.yaml"))
    return mcp

def add_tools(mcp: FastMCP):
    """Adds example tools to the MCP server."""
    @mcp.tool
    def read_emails(sender: str, last_n: int = 1):
        """Read emails from a sender."""
        # In a real app, this would call the Gmail API
        return [{"subject": "Test Email", "body": "Hello!", "attachments": [], "timestamp": "2025-01-01T12:00:00Z"}]

    mcp.tool(read_emails)

if __name__ == "__main__":
    mcp = create_mcp_server()
    add_tools(mcp)
    mcp.run(transport="http", port=9001)
```

## Built-in Policies

The middleware comes with a set of built-in policies to cover common use cases.

### `tool_access`

Controls access to tools.

- **`allow`**: Allows calling the tool.
- **`deny`**: Denies calling the tool and raises a `PolicyViolationError`.
- **`elicit`**: Prompts the user for permission to call the tool.

### `field_access`

Controls access to fields in the result of a tool call.

- **`allow`**: Allows the field to be returned.
- **`deny`**: Redacts the field from the result.
- **`elicit`**: Prompts the user for permission to access the field.

### `allow_attempts`

Limits the number of times a tool can be called.

- **`allow:{n}`**: Allows the tool to be called `n` times. The middleware will automatically decrement the count on each call.

## Extending the Middleware

You can easily create your own policy enforcers using the `@policy_enforcer` decorator.

```python
# my_enforcers.py
from mcp_macaroon_middleware import policy_enforcer, Caveat
from typing import List

@policy_enforcer("my_custom_policy")
def enforce_my_custom_policy(caveat: Caveat, context, result, macaroon, *params) -> List[Caveat]:
    """A custom policy enforcer."""
    # Your custom logic here
    logger.info(f"Enforcing my custom policy: {caveat.raw}")
    return []
```

To load your custom enforcers, simply import the module where they are defined in your main application, before you initialize the middleware.

## Running the Example

To run the example server:

1.  **Install dependencies:**
    ```bash
    pip install -e .
    # You might need to install fastmcp and other dependencies separately
    ```
2.  **Set environment variables:**
    ```bash
    export GITHUB_CLIENT_ID="your_github_client_id"
    export GITHUB_CLIENT_SECRET="your_github_client_secret"
    ```
3.  **Run the server:**
    ```bash
    python examples/server.py
    ```

## Development

### Running Tests

To run the unit tests, first ensure you have installed the development dependencies:

```bash
pip install -e '.[dev]'
```

Then, run pytest from the project root:

```bash
pytest
```

### Versioning and Releases

This project uses `bump2version` for managing versions and creating releases. To update the version and create a new Git tag, use the following commands:

```bash
bump2version [patch|minor|major]
```

For example, to increment the patch version:

```bash
bump2version patch
```

This will update the `version` in `pyproject.toml`, commit the change, and create a Git tag. Pushing this tag to GitHub will trigger the CI/CD pipeline to build and publish the package to PyPI.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

This project is licensed under the MIT License.