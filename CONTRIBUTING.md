# Contributing to MCP Macaroon Middleware

We welcome contributions to the MCP Macaroon Middleware project! To ensure a smooth and effective collaboration, please follow these guidelines.

## How to Contribute

1.  **Fork the Repository**: Start by forking the [project repository](https://github.com/indreshp135/MCP-MIDDLEWARE) to your GitHub account.
2.  **Clone Your Fork**: Clone your forked repository to your local machine:

    ```bash
    git clone https://github.com/your-username/MCP-MIDDLEWARE.git
    cd MCP-MACAROON-MIDDLEWARE
    ```

3.  **Create a New Branch**: Create a new branch for your feature or bug fix. Use a descriptive name (e.g., `feat/add-new-policy`, `fix/macaroon-deserialization-bug`).

    ```bash
    git checkout -b feat/your-feature-name
    ```

4.  **Set up Your Development Environment**: Install the project in editable mode with development dependencies:

    ```bash
    pip install -e '.[dev]'
    ```

5.  **Make Your Changes**: Implement your feature or bug fix. Ensure your code adheres to the existing style and conventions of the project.

6.  **Write Tests**: For new features, write comprehensive unit tests. For bug fixes, add a test that reproduces the bug and then verifies the fix.

7.  **Run Tests**: Before submitting, make sure all tests pass:

    ```bash
    pytest
    ```

8.  **Update Documentation**: If your changes introduce new features or alter existing behavior, update the `README.md` or other relevant documentation.

9.  **Commit Your Changes**: Commit your changes with a clear and concise commit message. Follow the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification (e.g., `feat: Add new policy type`, `fix: Resolve macaroon parsing error`).

    ```bash
    git commit -m "feat: Add a new policy enforcer for resource limits"
    ```

10. **Push to Your Fork**: Push your changes to your fork on GitHub:

    ```bash
    git push origin feat/your-feature-name
    ```

11. **Open a Pull Request**: Go to the original project repository on GitHub and open a pull request from your new branch. Provide a detailed description of your changes and reference any related issues.

## Code Style

- Adhere to [PEP 8](https://www.python.org/dev/peps/pep-0008/) for Python code.
- Use meaningful variable and function names.
- Keep functions and methods concise and focused on a single responsibility.

## Reporting Bugs

If you find a bug, please open an issue on the [Bug Tracker](https://github.com/indreshp135/MCP-MIDDLEWARE/issues). Include the following information:

- A clear and concise description of the bug.
- Steps to reproduce the behavior.
- Expected behavior.
- Actual behavior.
- Any relevant error messages or logs.
- Your environment details (Python version, installed dependencies).

## Feature Requests

For feature requests, please open an issue on the [Bug Tracker](https://github.com/indreshp135/MCP-MIDDLEWARE/issues) and describe:

- The problem you're trying to solve.
- The proposed solution.
- Any alternatives you've considered.

Thank you for your contributions!
