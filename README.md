# MCP Macaroon Middleware

A production-grade, policy-as-code middleware for `FastMCP` servers that uses macaroons for fine-grained, dynamic, and capability-based authorization.

This middleware allows you to enforce policies on tool calls, both before and after execution, using a simple yet powerful caveat system. Policies are defined in a human-readable YAML file and enforced by custom Python functions, giving you complete control over your MCP server's security.

## Key Features

- **Policy-as-Code:** Define authorization policies in a simple YAML file.
- **Pre & Post Enforcement:** Apply policies before a tool is called and/or on the result of the tool call.
- **Extensible:** Easily add new policy enforcement logic using a decorator-based system.
- **Capability-Based Security:** Leverages macaroons to issue time-bound, attenuated credentials.
- **Field-Level Control:** Redact or allow specific fields in tool outputs.

## Installation

Assuming this middleware is packaged and available on a package repository like PyPI:

```bash
pip install mcp-macaroon-middleware
```

## Configuration

The middleware is configured through a YAML file that specifies the initial set of caveats to be added to newly created macaroons.

Create a `policies.yaml` file (or any name you prefer) with a `policies` key:

```yaml
# config/policies.yaml
policies:
  # Allow calling 'read_emails' before execution
  - "bf:read_emails:*:allow:2026-01-01T00:00:00Z"

  # After 'get_user_profile' is called, allow access to these fields
  - "af:get_user_profile:user_id:allow:2026-01-01T00:00:00Z"
  - "af:get_user_profile:login:allow:2026-01-01T00:00:00Z"
  - "af:get_user_profile:name:allow:2026-01-01T00:00:00Z"

  # Redact the 'email' field from the result of 'get_user_profile'
  - "af:get_user_profile:email:redact:2026-01-01T00:00:00Z"
```

### Caveat Format

The caveat format is as follows:

`{phase}:{tool_name}:{field_path}:{action}:{expiry}`

- **`phase`**: `bf` (before) or `af` (after) the tool call.
- **`tool_name`**: The name of the tool to which the policy applies.
- **`field_path`**: The field in the tool's input or output to which the policy applies. Use `*` for all fields.
- **`action`**: The action to take (e.g., `allow`, `redact`, `deny`). This is interpreted by your policy enforcement function.
- **`expiry`**: An ISO 8601 timestamp (UTC) for when the caveat expires.

## Usage

Here's how to integrate the `MacaroonMiddleware` into your `FastMCP` server.

### 1. Add the Middleware to your Server

In your main server file, import and add the `MacaroonMiddleware`.

```python
# server.py
import os
import logging
from fastmcp import FastMCP, Context
from fastmcp.server.auth.providers.github import GitHubProvider
from mcp_macaroon_middleware import MacaroonMiddleware, policy_enforcer, PolicyViolationError

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_mcp_server():
    """Create an MCP server with Macaroon authentication."""
    GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID")
    GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET")
    BASE_URL = os.environ.get("BASE_URL", "http://localhost:9000")

    if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
        raise ValueError("GitHub credentials must be set.")

    auth_provider = GitHubProvider(
        client_id=GITHUB_CLIENT_ID,
        client_secret=GITHUB_CLIENT_SECRET,
        base_url=BASE_URL,
    )

    mcp = FastMCP(name="My Secure Server", auth=auth_provider)

    # Add the macaroon middleware with the path to your policy config
    mcp.add_middleware(MacaroonMiddleware("config/policies.yaml"))

    return mcp

# ... (rest of your server code)
```

### 2. Create Policy Enforcement Functions

Use the `@policy_enforcer` decorator to create functions that enforce your policies. The middleware will automatically discover and use these functions based on the `tool_name` in the caveat.

```python
# server.py (continued)

@policy_enforcer("get_user_profile")
def enforce_user_profile_policy(caveat, context, result):
    """
    Enforces policies on the 'get_user_profile' tool result.
    """
    # This function is called for the 'af' (after) phase
    if caveat.action == "redact" and result and caveat.field_path in result:
        logger.info(f"Redacting field: {caveat.field_path}")
        result[caveat.field_path] = "REDACTED"
    elif caveat.action == "allow":
        # 'allow' is a pass-through action in this example
        pass
    else:
        raise PolicyViolationError(f"Action '{caveat.action}' is not supported.")

# ...
```

### 3. Define Your Tools

Create your tools as you normally would with `FastMCP`.

```python
# server.py (continued)

def add_tools(mcp: FastMCP):
    @mcp.tool
    async def get_user_profile(ctx: Context):
        """Get the authenticated user's profile."""
        # In a real app, you would fetch this from a database or API
        return {
            "user_id": "12345",
            "login": "testuser",
            "name": "Test User",
            "email": "test@example.com"
        }

if __name__ == "__main__":
    mcp = create_mcp_server()
    add_tools(mcp)
    mcp.run(transport="http", port=9000)
```

When a user calls the `get_user_profile` tool, the `MacaroonMiddleware` will intercept the result. Based on the `policies.yaml` configuration, it will call the `enforce_user_profile_policy` function, which will redact the `email` field before returning the result to the user.

## License

This project is licensed under the MIT License.
