"""
Legacy Combined Authorization Server + Resource Server for MCP.

This server implements the old spec where MCP servers could act as both AS and RS.
Used for backwards compatibility testing with the new split AS/RS architecture.

Usage:
    python -m mcp_simple_auth.legacy_as_server --port=8002
"""

import logging
from typing import Any, Literal

import click
from pydantic import AnyHttpUrl
from pydantic_settings import SettingsConfigDict
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.server.fastmcp.server import FastMCP

from .github_oauth_provider import GitHubOAuthProvider, GitHubOAuthSettings

logger = logging.getLogger(__name__)


class ServerSettings(GitHubOAuthSettings):
    """Settings for the simple GitHub MCP server."""

    model_config = SettingsConfigDict(env_prefix="MCP_")

    # Server settings
    host: str = "localhost"
    port: int = 8000
    server_url: AnyHttpUrl = AnyHttpUrl("http://localhost:8000")
    github_callback_path: str = "http://localhost:8000/github/callback"

    def __init__(self, **data):
        """Initialize settings with values from environment variables.

        Note: github_client_id and github_client_secret are required but can be
        loaded automatically from environment variables (MCP_GITHUB_CLIENT_ID
        and MCP_GITHUB_CLIENT_SECRET) and don't need to be passed explicitly.
        """
        super().__init__(**data)


class SimpleGitHubOAuthProvider(GitHubOAuthProvider):
    """GitHub OAuth provider for legacy MCP server."""

    def __init__(self, settings: ServerSettings):
        super().__init__(settings, settings.github_callback_path)


def create_simple_mcp_server(settings: ServerSettings) -> FastMCP:
    """Create a simple FastMCP server with GitHub OAuth."""
    oauth_provider = SimpleGitHubOAuthProvider(settings)

    auth_settings = AuthSettings(
        issuer_url=settings.server_url,
        client_registration_options=ClientRegistrationOptions(
            enabled=True,
            valid_scopes=[settings.mcp_scope],
            default_scopes=[settings.mcp_scope],
        ),
        required_scopes=[settings.mcp_scope],
        # No authorization_servers parameter in legacy mode
        authorization_servers=None,
    )

    app = FastMCP(
        name="Simple GitHub MCP Server",
        instructions="A simple MCP server with GitHub OAuth authentication",
        auth_server_provider=oauth_provider,
        host=settings.host,
        port=settings.port,
        debug=True,
        auth=auth_settings,
    )

    @app.custom_route("/github/callback", methods=["GET"])
    async def github_callback_handler(request: Request) -> Response:
        """Handle GitHub OAuth callback."""
        code = request.query_params.get("code")
        state = request.query_params.get("state")

        if not code or not state:
            raise HTTPException(400, "Missing code or state parameter")

        try:
            redirect_uri = await oauth_provider.handle_github_callback(code, state)
            return RedirectResponse(status_code=302, url=redirect_uri)
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Unexpected error", exc_info=e)
            return JSONResponse(
                status_code=500,
                content={
                    "error": "server_error",
                    "error_description": "Unexpected error",
                },
            )

    def get_github_token() -> str:
        """Get the GitHub token for the authenticated user."""
        access_token = get_access_token()
        if not access_token:
            raise ValueError("Not authenticated")

        # Get GitHub token from mapping
        github_token = oauth_provider.token_mapping.get(access_token.token)

        if not github_token:
            raise ValueError("No GitHub token found for user")

        return github_token

    @app.tool()
    async def get_user_profile() -> dict[str, Any]:
        """Get the authenticated user's GitHub profile information.

        This is the only tool in our simple example. It requires the 'user' scope.
        """
        access_token = get_access_token()
        if not access_token:
            raise ValueError("Not authenticated")

        return await oauth_provider.get_github_user_info(access_token.token)

    return app


@click.command()
@click.option("--port", default=8000, help="Port to listen on")
@click.option("--host", default="localhost", help="Host to bind to")
@click.option(
    "--transport",
    default="streamable-http",
    type=click.Choice(["sse", "streamable-http"]),
    help="Transport protocol to use ('sse' or 'streamable-http')",
)
def main(port: int, host: str, transport: Literal["sse", "streamable-http"]) -> int:
    """Run the simple GitHub MCP server."""
    logging.basicConfig(level=logging.INFO)

    try:
        # No hardcoded credentials - all from environment variables
        server_url = f"http://{host}:{port}"
        settings = ServerSettings(
            host=host,
            port=port,
            server_url=AnyHttpUrl(server_url),
            github_callback_path=f"{server_url}/github/callback",
        )
    except ValueError as e:
        logger.error("Failed to load settings. Make sure environment variables are set:")
        logger.error("  MCP_GITHUB_CLIENT_ID=<your-client-id>")
        logger.error("  MCP_GITHUB_CLIENT_SECRET=<your-client-secret>")
        logger.error(f"Error: {e}")
        return 1

    mcp_server = create_simple_mcp_server(settings)
    logger.info(f"Starting server with {transport} transport")
    mcp_server.run(transport=transport)
    return 0


if __name__ == "__main__":
    main()  # type: ignore[call-arg]
