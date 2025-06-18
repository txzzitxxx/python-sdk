"""
MCP Resource Server with Token Introspection.

This server validates tokens via Authorization Server introspection and serves MCP resources.
Demonstrates RFC 9728 Protected Resource Metadata for AS/RS separation.

Usage:
    python -m mcp_simple_auth.server --port=8001 --auth-server=http://localhost:9000
"""

import logging
from typing import Any, Literal

import click
import httpx
from pydantic import AnyHttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict
from starlette.authentication import AuthCredentials, AuthenticationBackend
from starlette.requests import HTTPConnection
from starlette.responses import JSONResponse

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from mcp.server.fastmcp.server import FastMCP
from mcp.shared.auth import ProtectedResourceMetadata

logger = logging.getLogger(__name__)


class ResourceServerSettings(BaseSettings):
    """Settings for the MCP Resource Server."""

    model_config = SettingsConfigDict(env_prefix="MCP_RESOURCE_")

    # Server settings
    host: str = "localhost"
    port: int = 8001
    server_url: AnyHttpUrl = AnyHttpUrl("http://localhost:8001")

    # Authorization Server settings
    auth_server_url: AnyHttpUrl = AnyHttpUrl("http://localhost:9000")
    auth_server_introspection_endpoint: str = "http://localhost:9000/introspect"
    auth_server_github_user_endpoint: str = "http://localhost:9000/github/user"

    # MCP settings
    mcp_scope: str = "user"

    def __init__(self, **data):
        """Initialize settings with values from environment variables."""
        super().__init__(**data)


class TokenIntrospectionAuthBackend(AuthenticationBackend):
    """
    Authentication backend for Resource Server that validates tokens via AS introspection.

    This backend:
    1. Extracts Bearer tokens from Authorization header
    2. Calls Authorization Server's introspection endpoint
    3. Creates AuthenticatedUser from token info
    """

    def __init__(self, settings: ResourceServerSettings):
        self.settings = settings
        self.introspection_endpoint = settings.auth_server_introspection_endpoint

    async def authenticate(self, conn: HTTPConnection):
        auth_header = next(
            (conn.headers.get(key) for key in conn.headers if key.lower() == "authorization"),
            None,
        )
        if not auth_header or not auth_header.lower().startswith("bearer "):
            return None

        token = auth_header[7:]  # Remove "Bearer " prefix

        # Introspect token with Authorization Server
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    self.introspection_endpoint,
                    data={"token": token},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )

                if response.status_code != 200:
                    logger.debug(f"Token introspection failed with status {response.status_code}")
                    return None

                data = response.json()
                if not data.get("active", False):
                    logger.debug("Token is not active")
                    return None

                # Create auth info from introspection response
                auth_info = AccessToken(
                    token=token,
                    client_id=data.get("client_id", "unknown"),
                    scopes=data.get("scope", "").split() if data.get("scope") else [],
                    expires_at=data.get("exp"),
                )

                return AuthCredentials(auth_info.scopes), AuthenticatedUser(auth_info)

            except Exception:
                logger.exception("Token introspection failed")
                return None


def create_resource_server(settings: ResourceServerSettings) -> FastMCP:
    """
    Create MCP Resource Server with token introspection.

    This server:
    1. Provides protected resource metadata (RFC 9728)
    2. Validates tokens via Authorization Server introspection
    3. Serves MCP tools and resources
    """
    # Create FastMCP server WITHOUT auth settings (since we'll use custom middleware)
    # This avoids the FastMCP validation error that requires auth_server_provider
    app = FastMCP(
        name="MCP Resource Server",
        instructions="Resource Server that validates tokens via Authorization Server introspection",
        host=settings.host,
        port=settings.port,
        debug=True,
        # No auth settings - this is RS, not AS
    )

    # Add the protected resource metadata route using FastMCP's custom_route
    @app.custom_route("/.well-known/oauth-protected-resource", methods=["GET", "OPTIONS"])
    async def protected_resource_metadata(_request):
        """Handle requests for protected resource metadata."""
        metadata = ProtectedResourceMetadata(
            resource=settings.server_url,
            authorization_servers=[settings.auth_server_url],
            scopes_supported=[settings.mcp_scope],
            bearer_methods_supported=["header"],
        )
        # Convert to dict with string URLs for JSON serialization
        response_data = {
            "resource": str(metadata.resource),
            "authorization_servers": [str(url) for url in metadata.authorization_servers],
            "scopes_supported": metadata.scopes_supported,
            "bearer_methods_supported": metadata.bearer_methods_supported,
        }
        return JSONResponse(response_data)

    async def get_github_user_data() -> dict[str, Any]:
        """
        Get GitHub user data via Authorization Server proxy endpoint.

        This avoids exposing GitHub tokens to the Resource Server.
        The Authorization Server handles the GitHub API call and returns the data.
        """
        access_token = get_access_token()
        if not access_token:
            raise ValueError("Not authenticated")

        # Call Authorization Server's GitHub proxy endpoint
        async with httpx.AsyncClient() as client:
            response = await client.get(
                settings.auth_server_github_user_endpoint,
                headers={
                    "Authorization": f"Bearer {access_token.token}",
                },
            )

            if response.status_code != 200:
                raise ValueError(f"GitHub user data fetch failed: {response.status_code} - {response.text}")

            return response.json()

    @app.tool()
    async def get_user_profile() -> dict[str, Any]:
        """
        Get the authenticated user's GitHub profile information.

        This tool requires the 'user' scope and demonstrates how Resource Servers
        can access user data without directly handling GitHub tokens.
        """
        return await get_github_user_data()

    @app.tool()
    async def get_user_info() -> dict[str, Any]:
        """
        Get information about the currently authenticated user.

        Returns token and scope information from the Resource Server's perspective.
        """
        access_token = get_access_token()
        if not access_token:
            raise ValueError("Not authenticated")

        return {
            "authenticated": True,
            "client_id": access_token.client_id,
            "scopes": access_token.scopes,
            "token_expires_at": access_token.expires_at,
            "token_type": "Bearer",
            "resource_server": str(settings.server_url),
            "authorization_server": str(settings.auth_server_url),
        }

    return app


@click.command()
@click.option("--port", default=8001, help="Port to listen on")
@click.option("--host", default="localhost", help="Host to bind to")
@click.option("--auth-server", default="http://localhost:9000", help="Authorization Server URL")
@click.option(
    "--transport",
    default="streamable-http",
    type=click.Choice(["sse", "streamable-http"]),
    help="Transport protocol to use ('sse' or 'streamable-http')",
)
def main(port: int, host: str, auth_server: str, transport: Literal["sse", "streamable-http"]) -> int:
    """
    Run the MCP Resource Server.

    This server:
    - Provides RFC 9728 Protected Resource Metadata
    - Validates tokens via Authorization Server introspection
    - Serves MCP tools requiring authentication

    Must be used with a running Authorization Server.
    """
    logging.basicConfig(level=logging.INFO)

    try:
        # Parse auth server URL
        auth_server_url = AnyHttpUrl(auth_server)

        # Create settings
        server_url = f"http://{host}:{port}"
        settings = ResourceServerSettings(
            host=host,
            port=port,
            server_url=AnyHttpUrl(server_url),
            auth_server_url=auth_server_url,
            auth_server_introspection_endpoint=f"{auth_server}/introspect",
            auth_server_github_user_endpoint=f"{auth_server}/github/user",
        )
    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        logger.error("Make sure to provide a valid Authorization Server URL")
        return 1

    try:
        mcp_server = create_resource_server(settings)

        logger.info("=" * 80)
        logger.info("📦 MCP RESOURCE SERVER")
        logger.info("=" * 80)
        logger.info(f"🌐 Server URL: {settings.server_url}")
        logger.info(f"🔑 Authorization Server: {settings.auth_server_url}")
        logger.info("📋 Endpoints:")
        logger.info(f"   ┌─ Protected Resource Metadata: {settings.server_url}/.well-known/oauth-protected-resource")
        mcp_path = "sse" if transport == "sse" else "mcp"
        logger.info(f"   ├─ MCP Protocol: {settings.server_url}/{mcp_path}")
        logger.info(f"   └─ Token Introspection: {settings.auth_server_introspection_endpoint}")
        logger.info("")
        logger.info("🛠️  Available Tools:")
        logger.info("   ├─ get_user_profile() - Get GitHub user profile")
        logger.info("   └─ get_user_info() - Get authentication status")
        logger.info("")
        logger.info("🔍 Tokens validated via Authorization Server introspection")
        logger.info("📱 Clients discover Authorization Server via Protected Resource Metadata")
        logger.info("=" * 80)

        # Run the server - this should block and keep running
        mcp_server.run(transport=transport)
        logger.info("Server stopped")
        return 0
    except Exception as e:
        logger.error(f"Server error: {e}")
        logger.exception("Exception details:")
        return 1


if __name__ == "__main__":
    main()  # type: ignore[call-arg]
