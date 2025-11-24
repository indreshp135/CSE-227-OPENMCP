# MCP Macaroon Middleware

**A production-grade, policy-as-code middleware for FastMCP servers that uses macaroons for fine-grained, dynamic, and capability-based authorization.**

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Contributing](#contributing)
- [License](#license)

## Overview

`mcp_macaroon_middleware` is a robust and flexible policy-as-code middleware designed to secure FastMCP (Microservices Communication Protocol) servers using the power of macaroons. It provides fine-grained, dynamic, and capability-based authorization, allowing developers to define complex access control policies directly in code. This ensures that your microservices can enforce sophisticated security rules with minimal overhead, leveraging the decentralized and delegated authorization benefits of macaroons.

This middleware is ideal for applications requiring:
- **Decentralized Authorization:** Delegate authorization decisions without centralizing state.
- **Fine-Grained Access Control:** Specify precise permissions for specific actions and resources.
- **Context-Aware Policies:** Implement policies that adapt based on request context, macaroon caveats, and external data.
- **Reduced Trust:** Minimize the need for services to trust each other implicitly, as macaroons carry their own authorization logic.

## Features

- **Macaroon-Based Authorization:** Leverages `pymacaroons` for secure token handling.
- **Policy-as-Code:** Define authorization policies using Python, offering flexibility and version control.
- **FastMCP Integration:** Seamlessly integrates with `fastmcp` servers for request interception.
- **Dynamic Policy Enforcement:** Policies can be updated and enforced without service restarts (depending on configuration).
- **Redis Caching:** Supports Redis for efficient caching of policy decisions and macaroon validation, improving performance.
- **Extensible Policy Engine:** Easily extendable to support custom caveat evaluators and enforcement logic.
- **Detailed Error Handling:** Provides clear exceptions for authorization failures, aiding in debugging and user feedback.

## Installation

To install `mcp_macaroon_middleware`, use pip:

```bash
pip install mcp_macaroon_middleware
```

For development, you can install the development dependencies:

```bash
pip install "mcp_macaroon_middleware[dev]"
```

## Usage

Integrating the middleware into your FastMCP server involves a few steps:

1.  **Define your Policies:** Create Python modules that define your authorization policies. These policies will specify how macaroons are validated and what permissions they grant.

    *Example (`policies/my_service_policy.py`):*
    ```python
    # policies/my_service_policy.py
    from mcp_macaroon_middleware.core.policy_engine import PolicyEngine
    from mcp_macaroon_middleware.models.caveat import Caveat
    from mcp_macaroon_middleware.policies.decorators import enforce

    @enforce("my_service:read_data")
    async def can_read_data(caveats: list[Caveat], context: dict) -> bool:
        """
        Policy to check if the macaroon allows reading data.
        This is a simplified example; real policies would inspect caveats more deeply.
        """
        for caveat in caveats:
            if "has_permission = read" == caveat.payload:
                return True
        return False

    @enforce("my_service:write_data")
    async def can_write_data(caveats: list[Caveat], context: dict) -> bool:
        """
        Policy to check if the macaroon allows writing data.
        """
        for caveat in caveats:
            if "has_permission = write" == caveat.payload:
                return True
        return False
    ```

2.  **Configure and Apply Middleware:** Instantiate the `MacaroonMiddleware` and apply it to your FastMCP server.

    *Example (`server.py`):*
    ```python
    import asyncio
    from fastmcp.server import FastMCPServer
    from fastmcp.route import route
    from mcp_macaroon_middleware.core.middleware import MacaroonMiddleware
    from mcp_macaroon_middleware.config.loader import ConfigLoader
    from mcp_macaroon_middleware.policies.default_enforcers import METADATA_ENFORCER

    # Assuming you have a config.yaml or similar for policy paths and Redis
    # Example config:
    # ---
    # policy_directories:
    #   - "./policies"
    # redis:
    #   host: "localhost"
    #   port: 6379
    #   db: 0
    # ---

    # Load configuration (e.g., from examples/policies.yaml or a custom path)
    config = ConfigLoader().load_config()

    # Initialize the middleware with policy directories and optionally a Redis client
    middleware = MacaroonMiddleware(
        policy_directories=config.get("policy_directories", []),
        redis_config=config.get("redis")
    )

    app = FastMCPServer()

    @app.route("greet", middleware=middleware)
    async def greet(name: str):
        # This route will be protected by the middleware.
        # The macaroon must satisfy policies configured for "greet" (or default ones).
        return f"Hello, {name}!"

    @app.route("secure_data", middleware=middleware.enforce("my_service:read_data"))
    async def secure_data():
        # This route specifically requires the "my_service:read_data" capability
        return {"data": "This is highly sensitive information."}

    async def main():
        await app.start()
        print("FastMCP server started on port 8000")

    if __name__ == "__main__":
        asyncio.run(main())
    ```
    *Note: The `METADATA_ENFORCER` is a default enforcer that can be used directly or extended.*

3.  **Client-Side with Macaroons:** On the client side, you would obtain a macaroon (e.g., from an authentication service) and attach it to your FastMCP requests.

    *Example (conceptual client interaction):*
    ```python
    import httpx
    # Assuming you have a way to generate/obtain macaroons
    # from pymacaroons import Macaroon, MACAROON_V2
    # m = Macaroon(
    #     location='myloc',
    #     identifier='we used this for an id',
    #     key='this is our super secret key for signing',
    #     version=MACAROON_V2
    # )
    # m.add_first_party_caveat('has_permission = read')
    # serialized_macaroon = m.serialize()

    async def make_request(macaroon_token: str):
        async with httpx.AsyncClient() as client:
            headers = {"Authorization": f"Bearer {macaroon_token}"}
            # Example for "greet" endpoint
            response = await client.post("http://localhost:8000/greet", json={"name": "World"}, headers=headers)
            print(response.json())

            # Example for "secure_data" endpoint
            response = await client.post("http://localhost:8000/secure_data", headers=headers)
            print(response.json())

    # asyncio.run(make_request(serialized_macaroon))
    ```

## Configuration

The middleware can be configured via a YAML file (or other methods you integrate) to specify:

-   `policy_directories`: A list of paths where your policy modules are located. The `ConfigLoader` will automatically discover and load policies from these directories.
-   `redis`: Configuration for the Redis client (host, port, db) for caching and session management.

Refer to `examples/policies.yaml` for a typical configuration structure.

## Contributing

We welcome contributions! Please see our `CONTRIBUTING.md` for guidelines on how to contribute to this project.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
