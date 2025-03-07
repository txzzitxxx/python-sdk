"""
Integration tests for MCP authorization components.
"""

import base64
import hashlib
import json
import secrets
import time
from typing import Any, Dict, List, Optional, cast
from urllib.parse import urlparse, parse_qs

import anyio
from pydantic import AnyUrl
import pytest
import httpx
from starlette.applications import Starlette
from starlette.datastructures import MutableHeaders
from starlette.testclient import TestClient
from starlette.routing import Route, Router, Mount
from starlette.responses import RedirectResponse, JSONResponse, Response
from starlette.requests import Request
from starlette.middleware import Middleware

from mcp.server.auth.errors import InvalidTokenError
from mcp.server.auth.middleware.client_auth import ClientAuthMiddleware
from mcp.server.auth.provider import AuthorizationParams, OAuthServerProvider, OAuthRegisteredClientsStore
from mcp.server.auth.router import ClientRegistrationOptions, RevocationOptions, create_auth_router
from mcp.server.auth.types import AuthInfo
from mcp.shared.auth import (
    OAuthClientInformationFull,
    OAuthTokenRevocationRequest,
    OAuthTokens,
)
from mcp.server.fastmcp import FastMCP


# Mock client store for testing
class MockClientStore:
    def __init__(self):
        self.clients = {}
        
    async def get_client(self, client_id: str) -> Optional[OAuthClientInformationFull]:
        return self.clients.get(client_id)
        
    async def register_client(self, client_info: OAuthClientInformationFull) -> OAuthClientInformationFull:
        self.clients[client_info.client_id] = client_info
        return client_info


# Mock OAuth provider for testing
class MockOAuthProvider(OAuthServerProvider):
    def __init__(self):
        self.client_store = MockClientStore()
        self.auth_codes = {}  # code -> {client_id, code_challenge, redirect_uri}
        self.tokens = {}  # token -> {client_id, scopes, expires_at}
        self.refresh_tokens = {}  # refresh_token -> access_token
        
    @property
    def clients_store(self) -> OAuthRegisteredClientsStore:
        return self.client_store
        
    async def authorize(self, 
                     client: OAuthClientInformationFull, 
                     params: AuthorizationParams, 
                     response: Response):
        # Generate an authorization code
        code = f"code_{int(time.time())}"
        
        # Store the code for later verification
        self.auth_codes[code] = {
            "client_id": client.client_id,
            "code_challenge": params.code_challenge,
            "redirect_uri": params.redirect_uri,
            "expires_at": int(time.time()) + 600,  # 10 minutes
        }
        
        # Redirect with code
        query = {"code": code}
        if params.state:
            query["state"] = params.state
            
        redirect_url = f"{params.redirect_uri}?" + "&".join([f"{k}={v}" for k, v in query.items()])
        response.headers["location"] = redirect_url
        
    async def challenge_for_authorization_code(self, 
                                       client: OAuthClientInformationFull, 
                                       authorization_code: str) -> str:
        # Get the stored code info
        code_info = self.auth_codes.get(authorization_code)
        if not code_info:
            raise InvalidTokenError("Invalid authorization code")
            
        # Check if code is expired
        if code_info["expires_at"] < int(time.time()):
            raise InvalidTokenError("Authorization code has expired")
            
        # Check if the code was issued to this client
        if code_info["client_id"] != client.client_id:
            raise InvalidTokenError("Authorization code was not issued to this client")
            
        return code_info["code_challenge"]
        
    async def exchange_authorization_code(self, 
                                   client: OAuthClientInformationFull, 
                                   authorization_code: str) -> OAuthTokens:
        # Get the stored code info
        code_info = self.auth_codes.get(authorization_code)
        if not code_info:
            raise InvalidTokenError("Invalid authorization code")
            
        # Check if code is expired
        if code_info["expires_at"] < int(time.time()):
            raise InvalidTokenError("Authorization code has expired")
            
        # Check if the code was issued to this client
        if code_info["client_id"] != client.client_id:
            raise InvalidTokenError("Authorization code was not issued to this client")
            
        # Generate an access token and refresh token
        access_token = f"access_{secrets.token_hex(32)}"
        refresh_token = f"refresh_{secrets.token_hex(32)}"
        
        # Store the tokens
        self.tokens[access_token] = {
            "client_id": client.client_id,
            "scopes": ["read", "write"],
            "expires_at": int(time.time()) + 3600,
        }
        
        self.refresh_tokens[refresh_token] = access_token
        
        # Remove the used code
        del self.auth_codes[authorization_code]
        
        return OAuthTokens(
            access_token=access_token,
            token_type="bearer",
            expires_in=3600,
            scope="read write",
            refresh_token=refresh_token,
        )
        
    async def exchange_refresh_token(self, 
                              client: OAuthClientInformationFull, 
                              refresh_token: str, 
                              scopes: Optional[List[str]] = None) -> OAuthTokens:
        # Check if refresh token exists
        if refresh_token not in self.refresh_tokens:
            raise InvalidTokenError("Invalid refresh token")
            
        # Get the access token for this refresh token
        old_access_token = self.refresh_tokens[refresh_token]
        
        # Check if the access token exists
        if old_access_token not in self.tokens:
            raise InvalidTokenError("Invalid refresh token")
            
        # Check if the token was issued to this client
        token_info = self.tokens[old_access_token]
        if token_info["client_id"] != client.client_id:
            raise InvalidTokenError("Refresh token was not issued to this client")
            
        # Generate a new access token and refresh token
        new_access_token = f"access_{secrets.token_hex(32)}"
        new_refresh_token = f"refresh_{secrets.token_hex(32)}"
        
        # Store the new tokens
        self.tokens[new_access_token] = {
            "client_id": client.client_id,
            "scopes": scopes or token_info["scopes"],
            "expires_at": int(time.time()) + 3600,
        }
        
        self.refresh_tokens[new_refresh_token] = new_access_token
        
        # Remove the old tokens
        del self.refresh_tokens[refresh_token]
        del self.tokens[old_access_token]
        
        return OAuthTokens(
            access_token=new_access_token,
            token_type="bearer",
            expires_in=3600,
            scope=" ".join(scopes) if scopes else " ".join(token_info["scopes"]),
            refresh_token=new_refresh_token,
        )
        
    async def verify_access_token(self, token: str) -> AuthInfo:
        # Check if token exists
        if token not in self.tokens:
            raise InvalidTokenError("Invalid access token")
            
        # Get token info
        token_info = self.tokens[token]
        
        # Check if token is expired
        if token_info["expires_at"] < int(time.time()):
            raise InvalidTokenError("Access token has expired")
            
        return AuthInfo(
            token=token,
            client_id=token_info["client_id"],
            scopes=token_info["scopes"],
            expires_at=token_info["expires_at"],
        )
        
    async def revoke_token(self, 
                    client: OAuthClientInformationFull, 
                    request: OAuthTokenRevocationRequest) -> None:
        token = request.token
        
        # Check if it's a refresh token
        if token in self.refresh_tokens:
            access_token = self.refresh_tokens[token]
            
            # Check if this refresh token belongs to this client
            if self.tokens[access_token]["client_id"] != client.client_id:
                # For security reasons, we still return success
                return
                
            # Remove the refresh token and its associated access token
            del self.tokens[access_token]
            del self.refresh_tokens[token]
            
        # Check if it's an access token
        elif token in self.tokens:
            # Check if this access token belongs to this client
            if self.tokens[token]["client_id"] != client.client_id:
                # For security reasons, we still return success
                return
                
            # Remove the access token
            del self.tokens[token]
            
            # Also remove any refresh tokens that point to this access token
            for refresh_token, access_token in list(self.refresh_tokens.items()):
                if access_token == token:
                    del self.refresh_tokens[refresh_token]


@pytest.fixture
def mock_oauth_provider():
    return MockOAuthProvider()


@pytest.fixture
def auth_app(mock_oauth_provider):
    # Create auth router
    auth_router = create_auth_router(
        mock_oauth_provider,
        AnyUrl("https://auth.example.com"),
        AnyUrl("https://docs.example.com"),
        client_registration_options=ClientRegistrationOptions(
            enabled=True
        ),
        revocation_options=RevocationOptions(
            enabled=True
        )
    )
    
    # Create Starlette app
    app = Starlette(
        routes=[
            Mount("/", app=auth_router)
        ]
    )
    
    return app


@pytest.fixture
def test_client(auth_app) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=auth_app), base_url="https://mcptest.com")

class TestAuthEndpoints:
    @pytest.mark.anyio
    async def test_metadata_endpoint(self, test_client: httpx.AsyncClient):
        """Test the OAuth 2.0 metadata endpoint."""
        print("Sending request to metadata endpoint")
        response = await test_client.get("/.well-known/oauth-authorization-server")
        print(f"Got response: {response.status_code}")
        if response.status_code != 200:
            print(f"Response content: {response.content}")
        assert response.status_code == 200
        
        metadata = response.json()
        assert metadata["issuer"] == "https://auth.example.com"
        assert metadata["authorization_endpoint"] == "https://auth.example.com/authorize"
        assert metadata["token_endpoint"] == "https://auth.example.com/token"
        assert metadata["registration_endpoint"] == "https://auth.example.com/register"
        assert metadata["revocation_endpoint"] == "https://auth.example.com/revoke"
        assert metadata["response_types_supported"] == ["code"]
        assert metadata["code_challenge_methods_supported"] == ["S256"]
        assert metadata["token_endpoint_auth_methods_supported"] == ["client_secret_post"]
        assert metadata["grant_types_supported"] == ["authorization_code", "refresh_token"]
        assert metadata["service_documentation"] == "https://docs.example.com"
        
    @pytest.mark.anyio
    async def test_client_registration(self, test_client: httpx.AsyncClient, mock_oauth_provider: MockOAuthProvider):
        """Test client registration."""
        client_metadata = {
            "redirect_uris": ["https://client.example.com/callback"],
            "client_name": "Test Client",
            "client_uri": "https://client.example.com",
        }
        
        response = await test_client.post(
            "/register",
            json=client_metadata,
        )
        assert response.status_code == 201, response.content
        
        client_info = response.json()
        assert "client_id" in client_info
        assert "client_secret" in client_info
        assert client_info["client_name"] == "Test Client"
        assert client_info["redirect_uris"] == ["https://client.example.com/callback"]
        
        # Verify that the client was registered
        #assert await mock_oauth_provider.clients_store.get_client(client_info["client_id"]) is not None
        
    @pytest.mark.anyio
    async def test_authorization_flow(self, test_client: httpx.AsyncClient, mock_oauth_provider: MockOAuthProvider):
        """Test the full authorization flow."""
        # 1. Register a client
        client_metadata = {
            "redirect_uris": ["https://client.example.com/callback"],
            "client_name": "Test Client",
        }
        
        response = await test_client.post(
            "/register",
            json=client_metadata,
        )
        assert response.status_code == 201
        client_info = response.json()
        
        # 2. Create a PKCE challenge
        code_verifier = "some_random_verifier_string"
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).decode().rstrip("=")
        
        # 3. Request authorization
        response = await test_client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": client_info["client_id"],
                "redirect_uri": "https://client.example.com/callback",
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "state": "test_state",
            },
        )
        assert response.status_code == 302
        
        # 4. Extract the authorization code from the redirect URL
        redirect_url = response.headers["location"]
        parsed_url = urlparse(redirect_url)
        query_params = parse_qs(parsed_url.query)
        
        assert "code" in query_params
        assert query_params["state"][0] == "test_state"
        auth_code = query_params["code"][0]
        
        # 5. Exchange the authorization code for tokens
        response = await test_client.post(
            "/token",
            json={
                "grant_type": "authorization_code",
                "client_id": client_info["client_id"],
                "client_secret": client_info["client_secret"],
                "code": auth_code,
                "code_verifier": code_verifier,
            },
        )
        assert response.status_code == 200
        
        token_response = response.json()
        assert "access_token" in token_response
        assert "token_type" in token_response
        assert "refresh_token" in token_response
        assert "expires_in" in token_response
        assert token_response["token_type"] == "bearer"
        
        # 6. Verify the access token
        access_token = token_response["access_token"]
        refresh_token = token_response["refresh_token"]
        
        # Create a test client with the token
        auth_info = await mock_oauth_provider.verify_access_token(access_token)
        assert auth_info.client_id == client_info["client_id"]
        assert "read" in auth_info.scopes
        assert "write" in auth_info.scopes
        
        # 7. Refresh the token
        response = await test_client.post(
            "/token",
            json={
                "grant_type": "refresh_token",
                "client_id": client_info["client_id"],
                "client_secret": client_info["client_secret"],
                "refresh_token": refresh_token,
            },
        )
        assert response.status_code == 200
        
        new_token_response = response.json()
        assert "access_token" in new_token_response
        assert "refresh_token" in new_token_response
        assert new_token_response["access_token"] != access_token
        assert new_token_response["refresh_token"] != refresh_token
        
        # 8. Revoke the token
        response = await test_client.post(
            "/revoke",
            json={
                "client_id": client_info["client_id"],
                "client_secret": client_info["client_secret"],
                "token": new_token_response["access_token"],
            },
        )
        assert response.status_code == 200
        
        # Verify that the token was revoked
        with pytest.raises(InvalidTokenError):
            await mock_oauth_provider.verify_access_token(new_token_response["access_token"])


class TestFastMCPWithAuth:
    """Test FastMCP server with authentication."""
    
    @pytest.mark.anyio
    async def test_fastmcp_with_auth(self, mock_oauth_provider: MockOAuthProvider):
        """Test creating a FastMCP server with authentication."""
        # Create FastMCP server with auth provider
        mcp = FastMCP(
            auth_provider=mock_oauth_provider,
            auth_issuer_url="https://auth.example.com",
            require_auth=True,
        )
        
        # Add a test tool
        @mcp.tool()
        def test_tool(x: int) -> str:
            return f"Result: {x}"
        
        transport = httpx.ASGITransport(app=mcp.starlette_app()) # pyright: ignore
        test_client = httpx.AsyncClient(transport=transport, base_url="http://mcptest.com")
        
        # Test metadata endpoint
        response = await test_client.get("/.well-known/oauth-authorization-server")
        assert response.status_code == 200
        
        # Test that auth is required for protected endpoints
        response = await test_client.get("/test")
        assert response.status_code == 401
        
        # Test that public endpoints don't require auth
        response = await test_client.get("/public")
        assert response.status_code == 200
        
        # Register a client
        client_metadata = {
            "redirect_uris": ["https://client.example.com/callback"],
            "client_name": "Test Client",
        }
        
        response = await test_client.post(
            "/register",
            json=client_metadata,
        )
        assert response.status_code == 201
        client_info = response.json()
        
        # Create a PKCE challenge
        code_verifier = "some_random_verifier_string"
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).decode().rstrip("=")
        
        # Request authorization
        response = await test_client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": client_info["client_id"],
                "redirect_uri": "https://client.example.com/callback",
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "state": "test_state",
            },
        )
        assert response.status_code == 302
        
        # Extract the authorization code from the redirect URL
        redirect_url = response.headers["location"]
        parsed_url = urlparse(redirect_url)
        query_params = parse_qs(parsed_url.query)
        
        assert "code" in query_params
        auth_code = query_params["code"][0]
        
        # Exchange the authorization code for tokens
        response = await test_client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": client_info["client_id"],
                "client_secret": client_info["client_secret"],
                "code": auth_code,
                "code_verifier": code_verifier,
            },
        )
        assert response.status_code == 200
        
        token_response = response.json()
        assert "access_token" in token_response
        
        # Test the authenticated endpoint with valid token
        response = await test_client.get(
            "/test",
            headers={"Authorization": f"Bearer {token_response['access_token']}"},
        )
        assert response.status_code == 200
        assert response.json()["status"] == "ok"
        assert response.json()["client_id"] == client_info["client_id"]
        
        # Test with invalid token
        response = await test_client.get(
            "/test",
            headers={"Authorization": "Bearer invalid_token"},
        )
        assert response.status_code == 401