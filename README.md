# MCP Macaroon Middleware

**Production-grade macaroon-based authorization middleware for FastMCP servers with fine-grained, progressive policy enforcement.**

[![PyPI version](https://badge.fury.io/py/mcp-macaroon-middleware.svg)](https://badge.fury.io/py/mcp-macaroon-middleware)

## Overview

`mcp_macaroon_middleware` provides cryptographic capability-based authorization for FastMCP servers using macaroons. Unlike traditional OAuth/JWT tokens, macaroons support **attenuation** (adding restrictions without re-signing), **offline verification**, and **progressive authorization** where permissions can be dynamically elicited from users.

**Key Benefits:**
- **Decentralized Authorization**: Verify tokens without callback to authorization server
- **Progressive Permissions**: Request additional permissions on-demand via user elicitation
- **Fine-Grained Control**: Pre-call and post-call policies with field-level access control
- **Policy-as-Code**: Define authorization rules as Python functions with full type safety

## Features

- 🔐 **Macaroon-based tokens** with cryptographic verification
- 📋 **Flexible policy system** with pre-call and post-call execution stages
- 🎯 **Built-in enforcers** for tool access, field redaction, and rate limiting
- 🔄 **Progressive authorization** via user elicitation with time-bound grants
- 🎨 **Pluggable architecture** for custom policy enforcers
- ⚡ **In-memory caching** with per-user macaroon state
- 🛡️ **FastMCP integration** via standard middleware hooks

## Installation

```bash
pip install mcp-macaroon-middleware
```

For development:

```bash
pip install -e '.[dev]'
```

## Quick Start

### 1. Define Policies (policies.yaml)

```yaml
config:
  secret_key: "your-secret-key-here"
  elicit_expiry: 3600  # Permission grants valid for 1 hour

policies:
  # Tool-level access control
  - "bf:read_emails:tool_access:allow"
  
  # Rate limiting (2 attempts)
  - "bf:read_emails:allow_attempts:allow:2"
  
  # Field-level permissions
  - "af:read_emails:field_access:allow:subject"
  - "af:read_emails:field_access:deny:body"
  - "af:read_emails:field_access:elicit:attachments"
```

**Caveat Format**: `{phase}:{tool}:{policy}:{action}:{params...}`

- **Phase**: `bf` (before call) or `af` (after call)
- **Action**: `allow`, `deny`, or `elicit` (prompt user)
- **Params**: Policy-specific parameters (fields, counts, etc.)

### 2. Create FastMCP Server

```python
from fastmcp import FastMCP
from fastmcp.server.auth.providers.github import GitHubProvider
from mcp_macaroon_middleware import MacaroonMiddleware

# Initialize with OAuth provider
auth_provider = GitHubProvider(
    client_id=GITHUB_CLIENT_ID,
    client_secret=GITHUB_CLIENT_SECRET,
    base_url="http://localhost:9001"
)

mcp = FastMCP(name="Secure API", auth=auth_provider)

# Add macaroon middleware
mcp.add_middleware(MacaroonMiddleware(config_path="./policies.yaml"))

@mcp.tool
def read_emails(sender: str, last_n: int = 1):
    """Read emails with field-level authorization."""
    return [
        {
            "subject": "Meeting Tomorrow",
            "body": "Let's discuss the project...",
            "attachments": ["proposal.pdf"]
        }
    ]

mcp.run(transport="http", port=9001)
```

### 3. Request Flow

1. **Initial Request**: User authenticates via OAuth
2. **Macaroon Creation**: Middleware creates macaroon with policies from YAML
3. **Pre-call Enforcement**: Checks tool access and rate limits
4. **Tool Execution**: Your function runs normally
5. **Post-call Enforcement**: Applies field redaction or prompts for permissions
6. **Progressive Auth**: If `elicit` action, user prompted for permission
7. **Cached State**: Updated macaroon stored for subsequent requests

## Policy System

### Built-in Enforcers

#### Tool Access Control
```python
# In policies.yaml
- "bf:read_emails:tool_access:allow"    # Grant access
- "bf:send_email:tool_access:deny"      # Block access
```

#### Field-Level Redaction
```python
# Redact specific fields from responses
- "af:read_emails:field_access:deny:body"
- "af:read_emails:field_access:deny:attachments"
```

#### Progressive Authorization
```python
# Prompt user for permission on first access
- "af:read_emails:field_access:elicit:attachments"

# User prompted: "Grant permission for: af:read_emails:field_access:elicit:attachments?"
# If approved, adds time-bound caveat: "...elicit:attachments:time<20250324T120000Z"
```

#### Rate Limiting
```python
# Allow 3 calls, then deny
- "bf:api_call:allow_attempts:allow:3"
```

### Custom Enforcers

Create custom policies by registering enforcement functions:

```python
from mcp_macaroon_middleware import policy_enforcer, Caveat
from typing import List

@policy_enforcer("business_hours")
def enforce_business_hours(
    caveat: Caveat,
    context: Context,
    result: ToolResult,
    macaroon: Macaroon
) -> List[Caveat]:
    """Only allow access during business hours (9 AM - 5 PM)."""
    from datetime import datetime
    
    hour = datetime.now().hour
    if not (9 <= hour < 17):
        raise PolicyViolationError("Access only allowed during business hours")
    
    return []  # No new caveats to add
```

Use in policies.yaml:
```yaml
- "bf:sensitive_tool:business_hours:allow"
```

### Advanced Example: Document Ownership

```python
@policy_enforcer("document_owner")
def enforce_document_ownership(
    caveat: Caveat,
    context: Context,
    result: ToolResult,
    macaroon: Macaroon,
    document_id: str
) -> List[Caveat]:
    """Verify user owns the document."""
    user_id = context.get("user_id")
    
    # Check ownership in your DB
    if not db.check_owner(document_id, user_id):
        raise PolicyViolationError(f"User {user_id} doesn't own document {document_id}")
    
    return []
```

```yaml
# In policies.yaml - pass document_id as parameter
- "bf:get_document:document_owner:allow:doc_123"
```

## Architecture

```
┌─────────────────┐
│  OAuth Token    │
│  (GitHub, etc)  │
└────────┬────────┘
         │
         ▼
┌─────────────────────────┐
│  MacaroonMiddleware     │
│  • Creates macaroon     │
│  • Caches per-user      │
└────────┬────────────────┘
         │
         ▼
┌─────────────────────────┐
│   PolicyEngine          │
│  • Parse caveats        │
│  • Execute enforcers    │
│  • Handle elicitation   │
└────────┬────────────────┘
         │
    ┌────┴────┐
    ▼         ▼
┌───────┐ ┌───────┐
│ BEFORE│ │ AFTER │
│ phase │ │ phase │
└───────┘ └───────┘
    │         │
    ▼         ▼
 Tool      Field
Access   Redaction
```

## Configuration

### YAML Configuration

```yaml
config:
  secret_key: "..."           # Macaroon signing key
  elicit_expiry: 3600         # Permission grant TTL (seconds)

policies:
  - "bf:tool:policy:action:params..."
```

## Examples

See the `examples/` directory:
- `server.py` - Complete FastMCP server with GitHub OAuth
- `policies.yaml` - Sample policy configuration

Run the example:
```bash
cd examples
pip install -r requirements.txt
python server.py
```

## API Reference

### MacaroonMiddleware

```python
MacaroonMiddleware(config_path: str)
```

**Parameters:**
- `config_path`: Path to policies.yaml configuration file

**Methods:**
- `on_call_tool(context, call_next)`: Main middleware hook

### Policy Enforcer Decorator

```python
@policy_enforcer(policy_name: str)
def my_enforcer(
    caveat: Caveat,
    context: Context,
    result: ToolResult,
    macaroon: Macaroon,
    *params
) -> List[Caveat]:
    """
    Args:
        caveat: Parsed caveat object
        context: FastMCP request context
        result: Tool execution result (None for pre-call)
        macaroon: Current macaroon instance
        *params: Additional parameters from caveat string
    
    Returns:
        List of new caveats to add to macaroon
    """
    pass
```

### Caveat Model

```python
@dataclass
class Caveat:
    raw: str                          # Original caveat string
    execution_phase: ExecutionPhase   # BEFORE or AFTER
    tool_name: str                    # Target tool
    policy_name: str                  # Policy enforcer name
    action: ActionType                # ALLOW, DENY, or ELICIT
    params: Tuple[str, ...]          # Policy parameters
    expiry: Optional[datetime]        # Expiration time
```

## Development

### Running Tests

```bash
pytest
```

### Building

```bash
python -m build
```

### Version Bump

```bash
bump2version patch  # or minor, major
git push --tags
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security Considerations

- Store `secret_key` securely (use environment variables or secrets management)
- Use HTTPS in production to protect macaroon transmission
- Set appropriate `elicit_expiry` values for your use case
- Review and audit custom policy enforcers for security vulnerabilities
- Consider implementing additional caveats for IP restrictions, time windows, etc.

## License

MIT License - see [LICENSE](LICENSE) file.

## Citation

```bibtex
@software{mcp_macaroon_middleware,
  author = {Indresh Pradeepkumar, Neil Grover, Ravi Gadgil},
  title = {MCP Macaroon Middleware},
  year = {2025},
  url = {https://github.com/indreshp135/CSE-227-OPENMCP}
}
```

## Links

- **GitHub**: https://github.com/indreshp135/CSE-227-OPENMCP
- **PyPI**: https://pypi.org/project/mcp-macaroon-middleware/
- **Issues**: https://github.com/indreshp135/CSE-227-OPENMCP/issues
- **FastMCP**: https://github.com/jlowin/fastmcp
- **Macaroons Paper**: https://research.google/pubs/pub41892/