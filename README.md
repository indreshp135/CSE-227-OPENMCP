# MCP Macaroon Middleware

A production-grade, policy-as-code middleware for `FastMCP` servers that uses macaroons for fine-grained, dynamic, and capability-based authorization.

This middleware allows you to enforce policies on tool calls, both before and after execution, using a simple yet powerful caveat system. Policies are defined in a human-readable YAML file and enforced by custom Python functions, giving you complete control over your MCP server's security.

## Key Features

- **Policy-as-Code:** Define authorization policies in a simple YAML file.
- **Pre & Post Enforcement:** Apply policies before a tool is called and/or on the result of the tool call.
- **Extensible:** Easily add new policy enforcement logic using a decorator-based system.
- **Capability-Based Security:** Leverages macaroons to issue time-bound, attenuated credentials.
- **Field-Level Control:** Redact or allow specific fields in tool outputs.
- **Elicitation for Dynamic Permissions:** Dynamically request user consent for specific actions or data access at runtime.
- **Automatic Expiry for Elicited Permissions:** Permissions granted through elicitation can be configured to expire after a specified duration.

## Installation

To install the middleware from your local checkout, run the following command from the root of the project:

```bash
pip install .
```

For development, you can install the package in editable mode:

```bash
pip install -e .
```

## Configuration

The middleware is configured through a YAML file that specifies global settings and the initial set of caveats to be added to newly created macaroons.

Create a `policies.yaml` file (or any name you prefer) with a `config` and `policies` key:

```yaml
# config/policies.yaml
config:
  # Secret key for signing macaroons. It's recommended to use an environment variable for this.
  secret_key: "this_is_a_very_secret_key"
  # Default expiry for elicited permissions in seconds (e.g., 1 hour)
  elicit_expiry: 3600

policies:
  # Allow calling 'read_emails' before execution with a specific expiry
  - "bf:read_emails:tool_access:allow:time<20260101T000000Z"

  # After 'get_user_profile' is called, allow access to these fields with a specific expiry
  - "af:get_user_profile:user_profile_fields:allow:user_id:time<20260101T000000Z"
  - "af:get_user_profile:user_profile_fields:allow:login:time<20260101T000000Z"
  - "af:get_user_profile:user_profile_fields:allow:name:time<20260101T000000Z"

  # Redact the 'email' field from the result of 'get_user_profile' with a specific expiry
  - "af:get_user_profile:user_profile_fields:redact:email:time<20260101T000000Z"

  # Elicit permission for attachments when sending emails, with a default expiry
  - "bf:send_email:tool_access:elicit"
  - "af:send_email:email_fields:elicit:attachments"
```

### Caveat Format

The caveat format is as follows:

`{phase}:{tool_name}:{policy_name}:{action}[{params}]:time<{expiry_timestamp}>`

- **`phase`**: `bf` (before) or `af` (after) the tool call.
- **`tool_name`**: The name of the tool to which the policy applies.
- **`policy_name`**: The name of the policy enforcer to call (e.g., `tool_access`, `user_profile_fields`, `email_fields`).
- **`action`**: The action to take (`allow`, `deny`, `elicit`). This is interpreted by your policy enforcement function.
- **`params`**: Optional colon-separated parameters specific to the policy enforcer (e.g., `user_id:login:name` for `user_profile_fields`).
- **`time<{expiry_timestamp}>`**: An optional expiry timestamp in `YYYYMMDDTHHMMSSZ` format (UTC). If present, the caveat is only valid until this time. This part is automatically added for elicited permissions.

**Examples:**

- `bf:read_emails:tool_access:allow`: Allow access to `read_emails` indefinitely.
- `af:get_user_profile:user_profile_fields:allow:user_id:login:name:time<20260101T000000Z>`: Allow access to `user_id`, `login`, and `name` fields from `get_user_profile` until Jan 1, 2026.
- `af:send_email:email_fields:elicit:attachments`: Elicit user permission to send attachments when calling `send_email`. If granted, an `allow` caveat with a configurable expiry will be added.

## Usage

Here's how to integrate the `MacaroonMiddleware` into your `FastMCP` server. The middleware comes with built-in enforcers for common policies like `tool_access`, `field_access`, and `allow_attempts`.

### 1. Add the Middleware to your Server

In your main server file (e.g., `examples/server.py`), import and add the `MacaroonMiddleware`.

```python
# examples/server.py
import os
import logging
from fastmcp import FastMCP, Context
from fastmcp.server.auth.providers.github import GitHubProvider
from mcp_macaroon_middleware import MacaroonMiddleware

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

### 2. Define Your Tools

Create your tools as you normally would with `FastMCP`.

```python
# examples/server.py (continued)

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

When a user calls a tool, the `MacaroonMiddleware` will intercept the call and enforce the policies defined in your `policies.yaml` file using the built-in enforcers. For example, if you have a policy to redact the `email` field, the middleware will do so before returning the result to the user.

## License

This project is licensed under the MIT License.
