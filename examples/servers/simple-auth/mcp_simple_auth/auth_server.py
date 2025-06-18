"""
Authorization Server for MCP Split Demo.

This server handles OAuth flows, client registration, and token issuance.
Can be replaced with enterprise authorization servers like Auth0, Entra ID, etc.

Usage:
    python -m mcp_simple_auth.auth_server --port=9000
"""

import asyncio
import logging
import secrets
import time

import click
import httpx
from pydantic import AnyHttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict
from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from uvicorn import Config, Server

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    construct_redirect_uri,
)
from mcp.server.auth.routes import cors_middleware, create_auth_routes
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.shared._httpx_utils import create_mcp_http_client
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

logger = logging.getLogger(__name__)


class AuthServerSettings(BaseSettings):
    """Settings for the Authorization Server."""

    model_config = SettingsConfigDict(env_prefix="MCP_")

    # Server settings
    host: str = "localhost"
    port: int = 9000
    server_url: AnyHttpUrl = AnyHttpUrl("http://localhost:9000")

    # GitHub OAuth settings - MUST be provided via environment variables
    github_client_id: str  # Type: MCP_GITHUB_CLIENT_ID env var
    github_client_secret: str  # Type: MCP_GITHUB_CLIENT_SECRET env var
    github_callback_path: str = "http://localhost:9000/github/callback"

    # GitHub OAuth URLs
    github_auth_url: str = "https://github.com/login/oauth/authorize"
    github_token_url: str = "https://github.com/login/oauth/access_token"

    mcp_scope: str = "user"
    github_scope: str = "read:user"

    def __init__(self, **data):
        """Initialize settings with values from environment variables."""
        super().__init__(**data)


class GitHubProxyAuthProvider(OAuthAuthorizationServerProvider):
    """
    Authorization Server provider that proxies GitHub OAuth.

    This provider:
    1. Issues MCP tokens after GitHub authentication
    2. Stores token state for introspection by Resource Servers
    3. Maps MCP tokens to GitHub tokens for API access
    """

    def __init__(self, settings: AuthServerSettings):
        self.settings = settings
        self.clients: dict[str, OAuthClientInformationFull] = {}
        self.auth_codes: dict[str, AuthorizationCode] = {}
        self.tokens: dict[str, AccessToken] = {}
        self.state_mapping: dict[str, dict[str, str]] = {}
        # Store GitHub tokens with MCP tokens using the format:
        # {"mcp_token": "github_token"}
        self.token_mapping: dict[str, str] = {}

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        """Get OAuth client information."""
        return self.clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull):
        """Register a new OAuth client."""
        self.clients[client_info.client_id] = client_info

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        """Generate an authorization URL for GitHub OAuth flow."""
        state = params.state or secrets.token_hex(16)

        # Store the state mapping
        self.state_mapping[state] = {
            "redirect_uri": str(params.redirect_uri),
            "code_challenge": params.code_challenge,
            "redirect_uri_provided_explicitly": str(params.redirect_uri_provided_explicitly),
            "client_id": client.client_id,
        }

        # Build GitHub authorization URL
        auth_url = (
            f"{self.settings.github_auth_url}"
            f"?client_id={self.settings.github_client_id}"
            f"&redirect_uri={self.settings.github_callback_path}"
            f"&scope={self.settings.github_scope}"
            f"&state={state}"
        )

        return auth_url

    async def handle_github_callback(self, code: str, state: str) -> str:
        """Handle GitHub OAuth callback."""
        state_data = self.state_mapping.get(state)
        if not state_data:
            raise HTTPException(400, "Invalid state parameter")

        redirect_uri = state_data["redirect_uri"]
        code_challenge = state_data["code_challenge"]
        redirect_uri_provided_explicitly = state_data["redirect_uri_provided_explicitly"] == "True"
        client_id = state_data["client_id"]

        # Exchange code for token with GitHub
        async with create_mcp_http_client() as client:
            response = await client.post(
                self.settings.github_token_url,
                data={
                    "client_id": self.settings.github_client_id,
                    "client_secret": self.settings.github_client_secret,
                    "code": code,
                    "redirect_uri": self.settings.github_callback_path,
                },
                headers={"Accept": "application/json"},
            )

            if response.status_code != 200:
                raise HTTPException(400, "Failed to exchange code for token")

            data = response.json()

            if "error" in data:
                raise HTTPException(400, data.get("error_description", data["error"]))

            github_token = data["access_token"]

            # Create MCP authorization code
            new_code = f"mcp_{secrets.token_hex(16)}"
            auth_code = AuthorizationCode(
                code=new_code,
                client_id=client_id,
                redirect_uri=AnyHttpUrl(redirect_uri),
                redirect_uri_provided_explicitly=redirect_uri_provided_explicitly,
                expires_at=time.time() + 300,
                scopes=[self.settings.mcp_scope],
                code_challenge=code_challenge,
            )
            self.auth_codes[new_code] = auth_code

            # Store GitHub token with client_id for later mapping
            # IMPORTANT: Store with MCP client_id, not GitHub client_id
            self.tokens[github_token] = AccessToken(
                token=github_token,
                client_id=client_id,  # This is the MCP client_id from state mapping
                scopes=[self.settings.github_scope],
                expires_at=None,
            )
            logger.info(f"🔑 Stored GitHub token {github_token[:10]}... for MCP client {client_id}")

        del self.state_mapping[state]
        final_redirect = construct_redirect_uri(redirect_uri, code=new_code, state=state)
        logger.info(f"🔗 Final redirect URI: {final_redirect}")
        logger.info("   Expected callback: http://localhost:3000/callback")
        logger.info("   Redirect URI components:")
        logger.info(f"     - redirect_uri: {redirect_uri}")
        logger.info(f"     - new_code: {new_code}")
        logger.info(f"     - state: {state}")
        # Debug: Verify that the redirect URI looks correct
        if not final_redirect.startswith("http://localhost:3000/callback"):
            logger.warning("⚠️  POTENTIAL ISSUE: Final redirect URI doesn't start with expected callback base!")
            logger.warning("   Expected: http://localhost:3000/callback?...")
            logger.warning(f"   Actual:   {final_redirect}")
        else:
            logger.info("✅ Redirect URI format looks correct")
        logger.info("🚀 About to return final_redirect to GitHub callback handler")
        return final_redirect

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        """Load an authorization code."""
        auth_code_obj = self.auth_codes.get(authorization_code)
        if auth_code_obj:
            logger.info("🔍 LOADED AUTH CODE FOR VALIDATION:")
            logger.info(f"   - Code: {authorization_code}")
            logger.info(f"   - Stored redirect_uri: {auth_code_obj.redirect_uri}")
            logger.info(f"   - Client ID: {auth_code_obj.client_id}")
            logger.info(f"   - Redirect URI provided explicitly: {auth_code_obj.redirect_uri_provided_explicitly}")
        else:
            logger.warning(f"❌ AUTH CODE NOT FOUND: {authorization_code}")
            logger.warning(f"   Available codes: {list(self.auth_codes.keys())}")
        return auth_code_obj

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        """Exchange authorization code for tokens."""
        logger.info("🔄 STARTING TOKEN EXCHANGE")
        logger.info(f"   ✅ Code received: {authorization_code.code}")
        logger.info(f"   ✅ Client ID: {client.client_id}")
        logger.info(f"   📊 Available codes in storage: {list(self.auth_codes.keys())}")
        logger.info("   🔎 Code lookup in progress...")
        if authorization_code.code not in self.auth_codes:
            logger.error(f"❌ CRITICAL: Authorization code not found: {authorization_code.code}")
            logger.error(f"   Available codes: {list(self.auth_codes.keys())}")
            logger.error("   This indicates the code was either:")
            logger.error("     1. Already used and removed")
            logger.error("     2. Never created (redirect flow failed)")
            logger.error("     3. Expired and cleaned up")
            raise ValueError("Invalid authorization code")

        # Generate MCP access token
        mcp_token = f"mcp_{secrets.token_hex(32)}"
        logger.info(f"🎫 Generated MCP access token: {mcp_token[:10]}...")

        # Store MCP token
        self.tokens[mcp_token] = AccessToken(
            token=mcp_token,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=int(time.time()) + 3600,
        )
        logger.info("💾 Stored MCP token in server memory")

        # Find GitHub token for this client
        logger.info(f"🔍 Looking for GitHub token for client {client.client_id}")
        logger.info(f"   Available tokens: {[(t[:10] + '...', d.client_id) for t, d in self.tokens.items()]}")

        github_token = next(
            (
                token
                for token, data in self.tokens.items()
                # see https://github.blog/engineering/platform-security/behind-githubs-new-authentication-token-formats/
                # which you get depends on your GH app setup.
                if (token.startswith("ghu_") or token.startswith("gho_")) and data.client_id == client.client_id
            ),
            None,
        )

        if github_token:
            logger.info(f"✅ Found GitHub token {github_token[:10]}... for mapping")
        else:
            logger.warning("⚠️  No GitHub token found for client - user data access will be limited")

        # Store mapping between MCP token and GitHub token
        if github_token:
            self.token_mapping[mcp_token] = github_token

        logger.info(f"🧹 Cleaning up used authorization code: {authorization_code.code}")
        del self.auth_codes[authorization_code.code]
        logger.info("✅ Authorization code removed to prevent reuse")

        token_response = OAuthToken(
            access_token=mcp_token,
            token_type="Bearer",
            expires_in=3600,
            scope=" ".join(authorization_code.scopes),
        )
        logger.info("🎉 TOKEN EXCHANGE COMPLETE!")
        logger.info(f"   ✅ MCP access token: {mcp_token[:10]}...")
        logger.info("   ✅ Token type: Bearer")
        logger.info("   ✅ Expires in: 3600 seconds")
        logger.info(f"   ✅ Scopes: {authorization_code.scopes}")
        return token_response

    async def load_access_token(self, token: str) -> AccessToken | None:
        """Load and validate an access token."""
        access_token = self.tokens.get(token)
        if not access_token:
            return None

        # Check if expired
        if access_token.expires_at and access_token.expires_at < time.time():
            del self.tokens[token]
            return None

        return access_token

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> RefreshToken | None:
        """Load a refresh token - not supported."""
        return None

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        """Exchange refresh token"""
        raise NotImplementedError("Not supported")

    async def revoke_token(self, token: str, token_type_hint: str | None = None) -> None:
        """Revoke a token."""
        if token in self.tokens:
            del self.tokens[token]


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
        resource_url=settings.server_url,
        resource_name="MCP Authorization Server",
    )

    # Create OAuth routes
    routes = create_auth_routes(
        provider=oauth_provider,
        issuer_url=auth_settings.issuer_url,
        service_documentation_url=auth_settings.service_documentation_url,
        client_registration_options=auth_settings.client_registration_options,
        revocation_options=auth_settings.revocation_options,
        resource_url=settings.server_url,  # Enable protected resource metadata
        resource_name="MCP Authorization Server",
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
            logger.info(f"🔄 GitHub callback complete, redirecting to: {redirect_uri}")
            logger.info("   Redirect type: HTTP 302 (simple redirect)")

            from starlette.responses import RedirectResponse

            logger.info("🚀 Sending HTTP 302 redirect to client callback server...")
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

            # Look up GitHub token for this MCP token
            github_token = oauth_provider.token_mapping.get(mcp_token)
            if not github_token:
                return JSONResponse({"error": "no_github_token"}, status_code=404)

            # Call GitHub API with the stored GitHub token
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    "https://api.github.com/user",
                    headers={
                        "Authorization": f"Bearer {github_token}",
                        "Accept": "application/vnd.github.v3+json",
                    },
                )

                if response.status_code != 200:
                    return JSONResponse({"error": "github_api_error", "status": response.status_code}, status_code=502)

                return JSONResponse(response.json())

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
    logger.info("🔑 MCP AUTHORIZATION SERVER")
    logger.info("=" * 80)
    logger.info(f"🌐 Server URL: {settings.server_url}")
    logger.info("📋 Endpoints:")
    logger.info(f"   ┌─ OAuth Metadata:       {settings.server_url}/.well-known/oauth-authorization-server")
    logger.info(f"   ├─ Client Registration: {settings.server_url}/register")
    logger.info(f"   ├─ Authorization:       {settings.server_url}/authorize")
    logger.info(f"   ├─ Token Exchange:      {settings.server_url}/token")
    logger.info(f"   ├─ Token Introspection: {settings.server_url}/introspect")
    logger.info(f"   ├─ GitHub Callback:     {settings.server_url}/github/callback")
    logger.info(f"   └─ GitHub User Proxy:   {settings.server_url}/github/user")
    logger.info("")
    logger.info("🔍 Resource Servers should use /introspect to validate tokens")
    logger.info("📱 Configure GitHub App callback URL: " + settings.github_callback_path)
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
