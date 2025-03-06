"""
Router for OAuth authorization endpoints.

Corresponds to TypeScript file: src/server/auth/router.ts
"""

from dataclasses import dataclass
import re
from typing import Dict, List, Optional, Any, Union
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, APIRouter, Request, Response
from pydantic import AnyUrl, BaseModel

from mcp.server.auth.middleware.client_auth import ClientAuthDependency
from mcp.server.auth.provider import OAuthServerProvider
from mcp.shared.auth import OAuthMetadata
from mcp.server.auth.handlers.metadata import create_metadata_handler
from mcp.server.auth.handlers.authorize import create_authorization_handler
from mcp.server.auth.handlers.token import create_token_handler
from mcp.server.auth.handlers.revoke import create_revocation_handler


@dataclass
class ClientRegistrationOptions:
    enabled: bool = False
    client_secret_expiry_seconds: Optional[int] = None
    
@dataclass
class RevocationOptions:
    enabled: bool = False


def validate_issuer_url(url: AnyUrl):
    """
    Validate that the issuer URL meets OAuth 2.0 requirements.
    
    Args:
        url: The issuer URL to validate
        
    Raises:
        ValueError: If the issuer URL is invalid
    """
    
    # RFC 8414 requires HTTPS, but we allow localhost HTTP for testing
    if (url.scheme != "https" and
        url.host != "localhost" and
        not (url.host is not None and url.host.startswith("127.0.0.1"))):
        raise ValueError("Issuer URL must be HTTPS")
    
    # No fragments or query parameters allowed
    if url.fragment:
        raise ValueError("Issuer URL must not have a fragment")
    if url.query:
        raise ValueError("Issuer URL must not have a query string")


AUTHORIZATION_PATH = "/authorize"
TOKEN_PATH = "/token"
REGISTRATION_PATH = "/register"
REVOCATION_PATH = "/revoke"


def create_auth_router(
        provider: OAuthServerProvider,
        issuer_url: AnyUrl,
        service_documentation_url: AnyUrl | None = None,
        client_registration_options: ClientRegistrationOptions | None = None,
        revocation_options: RevocationOptions | None = None
    ) -> APIRouter:
    """
    Create a FastAPI application with standard MCP authorization endpoints.
    
    Corresponds to mcpAuthRouter in src/server/auth/router.ts
    
    Args:
        provider: OAuth server provider
        issuer_url: Issuer URL for the authorization server
        service_documentation_url: Optional URL for service documentation
        
    Returns:
        FastAPI application with authorization endpoints
    """

    validate_issuer_url(issuer_url)
    
    client_registration_options = client_registration_options or ClientRegistrationOptions()
    revocation_options = revocation_options or RevocationOptions()

    client_auth = ClientAuthDependency(provider.clients_store)
    
    auth_app = APIRouter()
    
    
    # Create handlers
    
    # Add routes
    metadata = build_metadata(issuer_url, service_documentation_url, client_registration_options, revocation_options)
    auth_app.add_api_route(
        "/.well-known/oauth-authorization-server",
        create_metadata_handler(metadata),
        methods=["GET"]
    )
    
    # NOTE: reviewed
    auth_app.add_api_route(
        AUTHORIZATION_PATH,
        create_authorization_handler(provider),
        methods=["GET", "POST"]
    )
    
    # Add token endpoint with client auth dependency
    # NOTE: reviewed
    auth_app.add_api_route(
        TOKEN_PATH,
        create_token_handler(provider),
        methods=["POST"],
        dependencies=[Depends(client_auth)]
    )
    
    # Add registration endpoint if supported
    if client_registration_options.enabled:
        from mcp.server.auth.handlers.register import create_registration_handler
        registration_handler = create_registration_handler(
            provider.clients_store,
            client_secret_expiry_seconds=client_registration_options.client_secret_expiry_seconds,
        )
        # NOTE: reviewed
        auth_app.add_api_route(
            REGISTRATION_PATH,
            registration_handler,
            methods=["POST"]
        )
    
    # Add revocation endpoint if supported
    if revocation_options.enabled:
    # NOTE: reviewed
        auth_app.add_api_route(
            REVOCATION_PATH,
            create_revocation_handler(provider),
            methods=["POST"],
            dependencies=[Depends(client_auth)]
        )
    
    return auth_app

def build_metadata(
        issuer_url: AnyUrl,
        service_documentation_url: Optional[AnyUrl],
        client_registration_options: ClientRegistrationOptions,
        revocation_options: RevocationOptions,
    ) -> Dict[str, Any]:
    issuer_url_str = str(issuer_url).rstrip("/")
    # Create metadata
    metadata = {
        "issuer": issuer_url_str,
        "service_documentation": str(service_documentation_url).rstrip("/") if service_documentation_url else None,
        
        "authorization_endpoint": f"{issuer_url_str}{AUTHORIZATION_PATH}",
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
        
        "token_endpoint": f"{issuer_url_str}{TOKEN_PATH}",
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
    }
    
    # Add registration endpoint if supported
    if client_registration_options.enabled:
        metadata["registration_endpoint"] = f"{issuer_url_str}{REGISTRATION_PATH}"
    
    # Add revocation endpoint if supported
    if revocation_options.enabled:
        metadata["revocation_endpoint"] = f"{issuer_url_str}{REVOCATION_PATH}"
        metadata["revocation_endpoint_auth_methods_supported"] = ["client_secret_post"]

    return metadata