"""
Authorization Server for MCP Split Demo.

This server handles OAuth flows, client registration, and token issuance.
Can be replaced with enterprise authorization servers like Auth0, Entra ID, etc.

Usage:
    python -m mcp_simple_auth.auth_server --port=9000
"""

import asyncio
import logging
import time

import click
from pydantic import AnyHttpUrl
from pydantic_settings import SettingsConfigDict
from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.routing import Route
from uvicorn import Config, Server

from mcp.server.auth.routes import cors_middleware, create_auth_routes
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions

from .github_oauth_provider import GitHubOAuthProvider, GitHubOAuthSettings

logger = logging.getLogger(__name__)


class AuthServerSettings(GitHubOAuthSettings):
    """Settings for the Authorization Server."""

    model_config = SettingsConfigDict(env_prefix="MCP_")

    # Server settings
    host: str = "localhost"
    port: int = 9000
    server_url: AnyHttpUrl = AnyHttpUrl("http://localhost:9000")
    github_callback_path: str = "http://localhost:9000/github/callback"

    def __init__(self, **data):
        """Initialize settings with values from environment variables."""
        super().__init__(**data)


class GitHubProxyAuthProvider(GitHubOAuthProvider):
    """
    Authorization Server provider that proxies GitHub OAuth.

    This provider:
    1. Issues MCP tokens after GitHub authentication
    2. Stores token state for introspection by Resource Servers
    3. Maps MCP tokens to GitHub tokens for API access
    """

    def __init__(self, settings: AuthServerSettings):
        super().__init__(settings, settings.github_callback_path)


def create_authorization_server(settings: AuthServerSettings) -> Starlette:
    """Create the Authorization Server application."""
    oauth_provider = GitHubProxyAuthProvider(settings)

    auth_settings = AuthSettings(
        issuer_url=settings.server_url,
        client_registration_options=ClientRegistrationOptions(
            enabled=True,
            valid_scopes=[settings.mcp_scope],
            default_scopes=[settings.mcp_scope],
        ),
        required_scopes=[settings.mcp_scope],
        authorization_servers=None,
    )

    # Create OAuth routes
    routes = create_auth_routes(
        provider=oauth_provider,
        issuer_url=auth_settings.issuer_url,
        service_documentation_url=auth_settings.service_documentation_url,
        client_registration_options=auth_settings.client_registration_options,
        revocation_options=auth_settings.revocation_options,
    )

    # Add GitHub callback route
    async def github_callback_handler(request: Request) -> Response:
        """Handle GitHub OAuth callback."""
        code = request.query_params.get("code")
        state = request.query_params.get("state")

        if not code or not state:
            raise HTTPException(400, "Missing code or state parameter")

        try:
            redirect_uri = await oauth_provider.handle_github_callback(code, state)
            return RedirectResponse(url=redirect_uri, status_code=302)
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

    routes.append(Route("/github/callback", endpoint=github_callback_handler, methods=["GET"]))

    # Add token introspection endpoint (RFC 7662) for Resource Servers
    async def introspect_handler(request: Request) -> Response:
        """
        Token introspection endpoint for Resource Servers.

        Resource Servers call this endpoint to validate tokens without
        needing direct access to token storage.
        """
        try:
            form = await request.form()
            token = form.get("token")
            if not token or not isinstance(token, str):
                return JSONResponse({"active": False}, status_code=400)

            # Look up token in provider
            access_token = await oauth_provider.load_access_token(token)
            if not access_token:
                return JSONResponse({"active": False})

            # Return token info for Resource Server
            return JSONResponse(
                {
                    "active": True,
                    "client_id": access_token.client_id,
                    "scope": " ".join(access_token.scopes),
                    "exp": access_token.expires_at,
                    "iat": int(time.time()),
                    "token_type": "Bearer",
                }
            )

        except Exception as e:
            logger.exception("Token introspection error")
            return JSONResponse({"active": False, "error": str(e)}, status_code=500)

    routes.append(
        Route(
            "/introspect",
            endpoint=cors_middleware(introspect_handler, ["POST", "OPTIONS"]),
            methods=["POST", "OPTIONS"],
        )
    )

    # Add GitHub user info endpoint (for Resource Server to fetch user data)
    async def github_user_handler(request: Request) -> Response:
        """
        Proxy endpoint to get GitHub user info using stored GitHub tokens.

        Resource Servers call this with MCP tokens to get GitHub user data
        without exposing GitHub tokens to clients.
        """
        try:
            # Extract Bearer token
            auth_header = request.headers.get("authorization", "")
            if not auth_header.startswith("Bearer "):
                return JSONResponse({"error": "unauthorized"}, status_code=401)

            mcp_token = auth_header[7:]

            # Get GitHub user info using the provider method
            try:
                user_info = await oauth_provider.get_github_user_info(mcp_token)
                return JSONResponse(user_info)
            except ValueError as e:
                if "No GitHub token found" in str(e):
                    return JSONResponse({"error": "no_github_token"}, status_code=404)
                elif "GitHub API error" in str(e):
                    return JSONResponse({"error": "github_api_error"}, status_code=502)
                raise

        except Exception as e:
            logger.exception("GitHub user info error")
            return JSONResponse({"error": str(e)}, status_code=500)

    routes.append(
        Route(
            "/github/user",
            endpoint=cors_middleware(github_user_handler, ["GET", "OPTIONS"]),
            methods=["GET", "OPTIONS"],
        )
    )

    return Starlette(debug=True, routes=routes)


async def run_server(settings: AuthServerSettings):
    """Run the Authorization Server."""
    auth_server = create_authorization_server(settings)

    config = Config(
        auth_server,
        host=settings.host,
        port=settings.port,
        log_level="info",
    )
    server = Server(config)

    logger.info("=" * 80)
    logger.info("MCP AUTHORIZATION SERVER")
    logger.info("=" * 80)
    logger.info(f"Server URL: {settings.server_url}")
    logger.info("Endpoints:")
    logger.info(f"  - OAuth Metadata: {settings.server_url}/.well-known/oauth-authorization-server")
    logger.info(f"  - Client Registration: {settings.server_url}/register")
    logger.info(f"  - Authorization: {settings.server_url}/authorize")
    logger.info(f"  - Token Exchange: {settings.server_url}/token")
    logger.info(f"  - Token Introspection: {settings.server_url}/introspect")
    logger.info(f"  - GitHub Callback: {settings.server_url}/github/callback")
    logger.info(f"  - GitHub User Proxy: {settings.server_url}/github/user")
    logger.info("")
    logger.info("Resource Servers should use /introspect to validate tokens")
    logger.info("Configure GitHub App callback URL: " + settings.github_callback_path)
    logger.info("=" * 80)

    await server.serve()


@click.command()
@click.option("--port", default=9000, help="Port to listen on")
@click.option("--host", default="localhost", help="Host to bind to")
def main(port: int, host: str) -> int:
    """
    Run the MCP Authorization Server.

    This server handles OAuth flows and can be used by multiple Resource Servers.

    Environment variables needed:
    - MCP_GITHUB_CLIENT_ID: GitHub OAuth Client ID
    - MCP_GITHUB_CLIENT_SECRET: GitHub OAuth Client Secret
    """
    logging.basicConfig(level=logging.INFO)

    try:
        settings = AuthServerSettings(host=host, port=port)
    except ValueError as e:
        logger.error("Failed to load settings. Make sure environment variables are set:")
        logger.error("  MCP_GITHUB_CLIENT_ID=<your-client-id>")
        logger.error("  MCP_GITHUB_CLIENT_SECRET=<your-client-secret>")
        logger.error(f"Error: {e}")
        return 1

    asyncio.run(run_server(settings))
    return 0


if __name__ == "__main__":
    main()  # type: ignore[call-arg]
