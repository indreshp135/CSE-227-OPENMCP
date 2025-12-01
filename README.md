# MCP Macaroon Middleware

**A production-grade, macaroon-based authorization middleware for Python applications, offering fine-grained, progressive, and policy-driven access control.**

[![PyPI version](https://badge.fury.io/py/mcp-macaroon-middleware.svg)](https://badge.fury.io/py/mcp-macaroon-middleware)

## Overview

`mcp_macaroon_middleware` provides cryptographic, capability-based authorization using macaroons. Unlike traditional OAuth/JWT tokens, macaroons enable advanced security patterns like **decentralized attenuation** (adding restrictions without re-signing), **offline verification**, and **progressive authorization**, where permissions can be dynamically requested from users in real-time.

This middleware is designed to solve common and complex authorization challenges, moving beyond simple "all-or-nothing" access. It allows you to protect sensitive functions, redact specific data fields, and enforce complex, context-aware rules with minimal boilerplate code. By externalizing authorization logic into a simple YAML file and extensible Python functions, it helps you build more secure, maintainable, and user-friendly applications.

**Key Benefits:**
- **Solve Over-Privileged Tokens**: Replace static API keys with short-lived, narrowly-scoped credentials that have fine-grained permissions.
- **Decentralized Authorization**: Verify tokens anywhere, without a network call to an authorization server, reducing latency and single points of failure.
- **Progressive Permissions**: Instead of requesting all permissions upfront, prompt users for approval only when they try to access a sensitive feature or data field.
- **Fine-Grained Control**: Enforce rules before a function executes (e.g., rate limiting, access control) and after it returns (e.g., redacting sensitive fields from a response).
- **Policy-as-Code**: Define authorization rules in a simple, auditable YAML file, separating policy from application logic.

## Core Concepts

`mcp_macaroon_middleware` is built on a few powerful concepts that enable flexible and secure authorization.

### 1. Policy-as-Code in YAML
Instead of hardcoding business rules in your application, you define them in a simple, human-readable YAML file. This separates authorization logic from your application code, making it easier to manage, audit, and update policies without redeploying your application.

```yaml
policies:
  # Deny access to a specific function before it's called
  - "bf:admin_tool:tool_access:deny"

  # Redact a sensitive field from an object after it's returned
  - "af:get_user_profile:field_access:deny:user_pii.social_security_number"

  # Ask the user for permission before accessing their attachments
  - "af:read_emails:field_access:elicit:attachments"
```

### 2. Two-Phase Policy Enforcement
Policies are enforced in two distinct phases, giving you complete control over your functions' execution lifecycle:

- **`bf` (Before-Call):** Executed *before* your function is called. Ideal for coarse-grained access control, rate limiting, or input validation. If a `deny` policy is triggered here, the function is never executed.
- **`af` (After-Call):** Executed *after* your function returns a result. Perfect for fine-grained response filtering, redacting sensitive data fields, or triggering side-effects based on the output.

### 3. Progressive Authorization via Elicitation
For actions that are sensitive but not always disallowed, you can use the `elicit` action. This will automatically prompt the user for real-time approval when they attempt the action. If the user grants permission, the middleware adds a temporary, time-bound caveat to their macaroon, allowing them to perform the action for a limited period without being prompted again. This provides a seamless user experience while maintaining a "least privilege" security posture.

### 4. Extensible Custom Enforcers
While the middleware comes with built-in policies for common use cases (like tool access and field redaction), its real power lies in its extensibility. You can easily create your own complex, context-aware authorization rules using a simple Python decorator.

Custom enforcers can inspect anything in the request context (like user roles, IP addresses, or request parameters) to make dynamic authorization decisions.

```python
# A custom enforcer that only allows access during business hours
@policy_enforcer("business_hours")
def enforce_business_hours(caveat: Caveat, context: Context, **kwargs) -> List[Caveat]:
    hour = datetime.now().hour
    if not (9 <= hour < 17):
        raise PolicyViolationError("Access only allowed during business hours")
    return [] # Success
```
You can then use this custom enforcer directly in your `policies.yaml`:
```yaml
policies:
  - "bf:sensitive_tool:business_hours:allow"
```

## How It Solves Common Security Problems

| Security Problem | How `mcp-macaroon-middleware` Solves It |
| :--- | :--- |
| **Over-Privileged API Keys** | Replaces static, long-lived API keys with short-lived, narrowly-scoped macaroons. Permissions can be attenuated (restricted) for specific tasks without needing a new token. |
| **Data Leakage / Accidental Exposure** | The `after-call` enforcement phase allows you to dynamically redact sensitive fields from API responses based on the requesting user's permissions, ensuring that clients only see the data they are authorized to see. |
| **Hardcoded Authorization Logic**| Moves authorization logic out of your application code and into a separate, auditable policy layer. This makes your codebase cleaner and your security rules easier to manage and reason about. |
| **Poor User Experience vs. Security** | The progressive authorization (`elicit`) feature provides a powerful middle ground between denying access and always allowing it. It improves security by default while giving users a frictionless way to grant permissions when needed. |
| **Centralized Bottlenecks** | Macaroons can be verified cryptographically without calling back to a central authorization server. This is ideal for distributed systems and reduces latency and single points of failure. |

## Installation

```bash
pip install mcp-macaroon-middleware
```

For development:

```bash
pip install -e '.[dev]'
```

## Quick Start

This guide provides a conceptual overview. For a runnable example, see the `examples/` directory.

### 1. Define Your Policies
Create a `policies.yaml` file to define your authorization rules.

```yaml
config:
  secret_key: "your-secret-key-here"
  elicit_expiry: 3600 # Elicited permissions are valid for 1 hour

policies:
  # Allow access to 'read_emails' but deny access to 'admin_tool'
  - "bf:read_emails:tool_access:allow"
  - "bf:admin_tool:tool_access:deny"
  
  # After 'read_emails' is called, deny access to the 'body' field
  - "af:read_emails:field_access:deny:body"

  # For the 'read_emails' function, prompt the user for permission to access 'attachments'
  - "af:read_emails:field_access:elicit:attachments"
```

### 2. Write a Custom Enforcer (Optional)
For more complex rules, create a custom enforcer function in your application and register it with the `@policy_enforcer` decorator.

```python
from mcp_macaroon_middleware import policy_enforcer, PolicyViolationError
from datetime import datetime

@policy_enforcer("business_hours")
def enforce_business_hours(caveat, context, **kwargs):
    """Only allow access between 9 AM and 5 PM."""
    hour = datetime.now().hour
    if not (9 <= hour < 17):
        raise PolicyViolationError("Access only allowed during business hours")
    return []
```
Then, reference it in your `policies.yaml`:
```yaml
- "bf:sensitive_tool:business_hours:allow"
```

### 3. Integrate the Middleware
In your application's request lifecycle, initialize `MacaroonMiddleware` and `PolicyEngine`. Then, invoke the policy engine at the appropriate stages.

```python
from mcp_macaroon_middleware import MacaroonMiddleware, PolicyEngine
from mcp_macaroon_middleware.core.policy_engine import RequestContext

# 1. Initialize the middleware (typically once at startup)
# This will load your policies from the YAML file.
middleware = MacaroonMiddleware(config_path="./policies.yaml")

# In your request handler / middleware layer:
async def handle_request(request):
    # 2. Get or create a macaroon for the user
    macaroon = await middleware._get_or_create_macaroon(request.user_id)

    # 3. Define the request context
    # This context is available to all policy enforcers
    context = RequestContext(
        user_id=request.user_id,
        # ... other relevant data like user roles, IP address, etc.
    )

    # 4. Enforce "before-call" policies
    # This happens before your main business logic
    modified_macaroon = await middleware.policy_engine.enforce_policies(
        macaroon,
        'bf', # ExecutionPhase.BEFORE
        tool_name="my_protected_function",
        context=context
    )
    
    # If no PolicyViolationError was raised, proceed.
    # 5. Execute your main business logic
    result = my_protected_function(request.params)

    # 6. Enforce "after-call" policies
    # This happens after your function returns, allowing you to filter the result
    final_result, modified_macaroon = await middleware.policy_engine.enforce_policies(
        macaroon,
        'af', # ExecutionPhase.AFTER
        tool_name="my_protected_function",
        context=context,
        result=result
    )
    
    # 7. The user receives the potentially redacted 'final_result'
    return final_result
```
*Note: The example above is a simplified, conceptual guide. The current `MacaroonMiddleware` class in `mcp_macaroon_middleware` provides a direct integration for the `FastMCP` framework.*

## Architecture

The middleware's architecture is composed of a few key components that work together to enforce authorization policies.

```
┌──────────────────┐
│  Initial Request │
│ (e.g., HTTP API) │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐      ┌─────────────────┐
│ Get or Create    ├──────► In-Memory Cache │
│ User Macaroon    │      │ (Per-User State)│
└────────┬─────────┘      └─────────────────┘
         │
         ▼
┌──────────────────┐      ┌─────────────────┐
│  Policy Engine   ├──────►  Policy & Custom│
│                  │      │    Enforcers    │
└────────┬─────────┘      └─────────────────┘
         │
    ┌────┴────┐
    ▼         ▼
┌───────┐ ┌───────┐
│ BEFORE│ │ AFTER │
│ Phase │ │ Phase │
└───────┘ └───────┘
    │         │
    ▼         ▼
 Function  Result
 Execution Redaction
```
## Framework and Developer Notes

### Framework Integration
The core logic of this middleware is framework-agnostic. The `PolicyEngine` is the central component that takes a macaroon, a set of policies, and a request context, and returns an authorization decision.

The `MacaroonMiddleware` class currently provides a convenient, out-of-the-box integration for the [FastMCP](https://github.com/jlowin/fastmcp) framework by implementing its `on_call_tool` hook.

**Adapting to Other Frameworks (e.g., FastAPI, Flask):**
To use this middleware with another web framework, you would create a new middleware class or decorator that:
1.  Initializes the `PolicyEngine` with your policies.
2.  Extracts user identity from the incoming request.
3.  Manages the lifecycle of the user's macaroon (e.g., retrieving it from a cache or creating a new one).
4.  Calls `policy_engine.enforce_policies` before and after your endpoint/controller logic is executed.
5.  Handles `PolicyViolationError` exceptions by returning an appropriate HTTP error (e.g., `403 Forbidden`).
6.  Manages the user prompt-and-response flow required for the `elicit` action.

### Production Considerations
- **Caching:** The default in-memory cache is for demonstration purposes and is tied to a single process. For production, multi-instance deployments, this should be replaced with a distributed cache like **Redis** to ensure that a user's macaroon state is consistent across all application servers.
- **Secret Management:** The `secret_key` used for signing macaroons should be treated as a sensitive secret. Load it from a secure source like an environment variable or a secret management service (e.g., HashiCorp Vault, AWS Secrets Manager).

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

See the `examples/` directory for a complete, runnable server using the `FastMCP` framework.
- `server.py` - Complete server with GitHub OAuth and custom enforcers.
- `policies.yaml` - Sample policy configuration for the server.

Run the example:
```bash
cd examples/github_example
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
- `on_call_tool(context, call_next)`: Main middleware hook for FastMCP.

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
        context: Request context containing user info
        result: Tool execution result (None for pre-call)
        macaroon: Current macaroon instance
        *params: Additional parameters from the caveat string
    
    Returns:
        A list of new caveats to add to the macaroon upon success.
    
    Raises:
        PolicyViolationError: If the authorization check fails.
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

- **Secret Key:** Store `secret_key` securely (use environment variables or secrets management).
- **Transport Security:** Use HTTPS in production to protect macaroons from being intercepted.
- **Elicitation Expiry:** Set appropriate `elicit_expiry` values. Short expiries are safer but may require users to grant permission more often.
- **Audit Custom Enforcers:** Carefully review and test custom policy enforcers for security vulnerabilities, as they are a critical part of your security model.
- **Input Validation:** While this middleware provides authorization, always validate and sanitize user-provided input in your main application logic.

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