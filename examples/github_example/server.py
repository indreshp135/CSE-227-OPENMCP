import logging
import requests
from fastmcp import FastMCP
from fastmcp.server.auth.providers.github import GitHubProvider
from mcp_macaroon_middleware import MacaroonMiddleware, policy_enforcer, PolicyViolationError
from fastmcp.server.middleware.middleware import mt, MiddlewareContext
import os

# --------------------------------------------------
# CONFIG – FILL THESE IN
# --------------------------------------------------
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET", "")
# Must match GitHub OAuth app callback base
BASE_URL = os.getenv("BASE_URL", "http://localhost:9001")
GITHUB_PAT = os.getenv("GITHUB_PAT", "")  # PAT with repo access

# --------------------------------------------------
# Logging
# --------------------------------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --------------------------------------------------
# GitHub OAuth Provider (for login only)
# --------------------------------------------------
auth_provider = GitHubProvider(
    client_id=GITHUB_CLIENT_ID,
    client_secret=GITHUB_CLIENT_SECRET,
    base_url=BASE_URL,
)

# --------------------------------------------------
# Helper: GitHub headers using PAT
# --------------------------------------------------


def github_headers() -> dict:
    return {
        "Authorization": f"Bearer {GITHUB_PAT}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

# --------------------------------------------------
# FastMCP Server (with macaroon middleware)
# --------------------------------------------------
mcp = FastMCP(name="GitHub Basic API", auth=auth_provider)

### Authorization Middleware ###
mcp.add_middleware(MacaroonMiddleware(
    config_path="examples/github_example/policies.yaml"))

@policy_enforcer("path_whitelist")
def enforce_path_whitelist(caveat, context: MiddlewareContext[mt.CallToolRequestParams], result, macaroon, *allowed_patterns):
    """Only allow access to specific file paths."""
    request_path = context.message.arguments.get("path", "")

    import fnmatch
    if not any(fnmatch.fnmatch(request_path, pattern) for pattern in allowed_patterns):
        raise PolicyViolationError(f"Access denied to path: {request_path}")
    return []

@policy_enforcer("repo_whitelist")
def enforce_repo_whitelist(caveat, context: MiddlewareContext[mt.CallToolRequestParams], result, macaroon, *allowed_repos):
    """Restrict access to specific repositories only."""
    repo_name = context.message.arguments.get("repo", "")

    if not repo_name:
        repo_name = context.message.arguments.get('name', '')

    if repo_name not in allowed_repos:
        raise PolicyViolationError(f"Access denied to repository: {repo_name}")
    return []

# ======================================================================
# USER TOOLS
# ======================================================================


@mcp.tool
def get_repo(owner: str, repo: str):
    """Fetch GitHub repository metadata."""
    logger.info("get_repo(%s/%s)", owner, repo)
    try:
        resp = requests.get(
            f"https://api.github.com/repos/{owner}/{repo}",
            headers=github_headers(),
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        logger.exception("get_repo failed: %s", e)
        return {"error": str(e)}


@mcp.tool
def list_issues(owner: str, repo: str, state: str = "open"):
    """List issues for a repository."""
    logger.info("list_issues(%s/%s)", owner, repo)
    try:
        resp = requests.get(
            f"https://api.github.com/repos/{owner}/{repo}/issues",
            params={"state": state},
            headers=github_headers(),
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        logger.exception("list_issues failed: %s", e)
        return {"error": str(e)}


@mcp.tool
def create_issue(owner: str, repo: str, title: str, body: str = ""):
    """Create a GitHub issue."""
    logger.info("create_issue(%s/%s)", owner, repo)
    try:
        resp = requests.post(
            f"https://api.github.com/repos/{owner}/{repo}/issues",
            headers=github_headers(),
            json={"title": title, "body": body},
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        logger.exception("create_issue failed: %s", e)
        return {"error": str(e)}


@mcp.tool
def read_file(owner: str, repo: str, path: str, ref: str = "main"):
    """Read a file from a GitHub repo."""
    full = f"{owner}/{repo}"
    logger.info("read_file(%s:%s)", full, path)
    try:
        resp = requests.get(
            f"https://api.github.com/repos/{full}/contents/{path}",
            params={"ref": ref},
            headers=github_headers(),
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()

        # GitHub returns file content base64-encoded
        if isinstance(data, dict) and data.get("encoding") == "base64":
            import base64
            decoded = base64.b64decode(data["content"]).decode("utf-8")
            data["decoded_content"] = decoded

        return data
    except Exception as e:
        logger.exception("read_file failed: %s", e)
        return {"error": str(e)}

# ======================================================================
# ADMIN-ONLY TOOLS
# ======================================================================


@mcp.tool
def create_repo(name: str, description: str = "", private: bool = True):
    """Create a new GitHub repo."""
    logger.info("create_repo(%s)", name)
    try:
        resp = requests.post(
            "https://api.github.com/user/repos",
            headers=github_headers(),
            json={
                "name": name,
                "description": description,
                "private": private,
            },
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        logger.exception("create_repo failed: %s", e)
        return {"error": str(e)}


@mcp.tool
def delete_repo(owner: str, repo: str):
    """Delete a GitHub repository."""
    full = f"{owner}/{repo}"
    logger.info("delete_repo(%s)", full)
    try:
        resp = requests.delete(
            f"https://api.github.com/repos/{full}",
            headers=github_headers(),
            timeout=10,
        )
        if resp.status_code == 204:
            return {"status": "deleted"}
        resp.raise_for_status()
        return {"status": "failed", "code": resp.status_code}
    except Exception as e:
        logger.exception("delete_repo failed: %s", e)
        return {"error": str(e)}


@mcp.tool
def add_collaborator(owner: str, repo: str, username: str, permission: str = "push"):
    """Add collaborator to a repo."""
    full = f"{owner}/{repo}"
    logger.info("add_collaborator(%s,%s)", full, username)
    try:
        resp = requests.put(
            f"https://api.github.com/repos/{full}/collaborators/{username}",
            headers=github_headers(),
            json={"permission": permission},
            timeout=10,
        )
        if resp.status_code in (201, 204):
            return {"status": "ok"}
        resp.raise_for_status()
    except Exception as e:
        logger.exception("add_collaborator failed: %s", e)
        return {"error": str(e)}


@mcp.tool
def write_file(owner: str, repo: str, path: str, content: str, message: str, sha: str = None, branch: str = "main"):
    """Create or update a file in a GitHub repo."""
    full = f"{owner}/{repo}"
    logger.info("write_file(%s:%s)", full, path)

    try:
        import base64
        encoded = base64.b64encode(content.encode("utf-8")).decode("utf-8")

        payload = {
            "message": message,
            "content": encoded,
            "branch": branch,
        }
        if sha:
            payload["sha"] = sha  # required for updating existing files

        resp = requests.put(
            f"https://api.github.com/repos/{full}/contents/{path}",
            headers=github_headers(),
            json=payload,
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()

    except Exception as e:
        logger.exception("write_file failed: %s", e)
        return {"error": str(e)}


@mcp.tool
def delete_file(owner: str, repo: str, path: str, sha: str, message: str, branch: str = "main"):
    """Delete a file from a GitHub repo."""
    full = f"{owner}/{repo}"
    logger.info("delete_file(%s:%s)", full, path)

    try:
        payload = {
            "message": message,
            "sha": sha,
            "branch": branch,
        }

        resp = requests.delete(
            f"https://api.github.com/repos/{full}/contents/{path}",
            headers=github_headers(),
            json=payload,
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()

    except Exception as e:
        logger.exception("delete_file failed: %s", e)
        return {"error": str(e)}

# ======================================================================
# RUN SERVER
# ======================================================================


if __name__ == "__main__":
    logger.info("Starting GitHub API Server at %s/mcp", BASE_URL)
    mcp.run(transport="http", port=9001)
