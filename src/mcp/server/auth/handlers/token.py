"""
Handler for OAuth 2.0 Token endpoint.

Corresponds to TypeScript file: src/server/auth/handlers/token.ts
"""

import base64
import hashlib
import json
from typing import Annotated, Any, Callable, Dict, List, Literal, Optional, Union

from starlette.requests import Request
from starlette.responses import JSONResponse
from pydantic import BaseModel, Field, RootModel, TypeAdapter, ValidationError

from mcp.server.auth.errors import (
    InvalidClientError,
    InvalidGrantError,
    InvalidRequestError,
    ServerError,
    UnsupportedGrantTypeError,
    OAuthError,
)
from mcp.server.auth.provider import OAuthServerProvider
from mcp.shared.auth import OAuthClientInformationFull, OAuthTokens
from mcp.server.auth.middleware.client_auth import ClientAuthRequest, ClientAuthenticator
from mcp.server.auth.json_response import PydanticJSONResponse

class AuthorizationCodeRequest(ClientAuthRequest):
    """
    Model for the authorization code grant request parameters.
    
    Corresponds to AuthorizationCodeExchangeSchema in src/server/auth/handlers/token.ts
    """
    grant_type: Literal["authorization_code"]
    code: str = Field(..., description="The authorization code")
    code_verifier: str = Field(..., description="PKCE code verifier")

class RefreshTokenRequest(ClientAuthRequest):
    """
    Model for the refresh token grant request parameters.
    
    Corresponds to RefreshTokenExchangeSchema in src/server/auth/handlers/token.ts
    """
    grant_type: Literal["refresh_token"]
    refresh_token: str = Field(..., description="The refresh token")
    scope: Optional[str] = Field(None, description="Optional scope parameter")


class TokenRequest(RootModel):
    root: Annotated[Union[AuthorizationCodeRequest, RefreshTokenRequest], Field(discriminator="grant_type")]
# TokenRequest = RootModel(Annotated[Union[AuthorizationCodeRequest, RefreshTokenRequest], Field(discriminator="grant_type")])


def create_token_handler(provider: OAuthServerProvider, client_authenticator: ClientAuthenticator) -> Callable:
    """
    Create a handler for the OAuth 2.0 Token endpoint.
    
    Corresponds to tokenHandler in src/server/auth/handlers/token.ts
    
    Args:
        provider: The OAuth server provider
        
    Returns:
        A Starlette endpoint handler function
    """
    
    async def token_handler(request: Request):
        """
        Handler for the OAuth 2.0 Token endpoint.
        
        Args:
            request: The Starlette request
            
        Returns:
            JSON response with tokens or error
        """
        # Parse request body as form data or JSON
        content_type = request.headers.get("Content-Type", "")

        try:
            token_request = TokenRequest.model_validate_json(await request.body()).root
        except ValidationError as e:
            raise InvalidRequestError(f"Invalid request body: {e}")
        client_info = await client_authenticator(token_request)
    
        tokens: OAuthTokens
        
        match token_request:
            case AuthorizationCodeRequest():
                # TODO: verify that the redirect URIs match; does the client actually provide this?
                # see https://datatracker.ietf.org/doc/html/rfc6749#section-10.6
                # TODO: enforce TTL on the authorization code

                # Verify PKCE code verifier
                expected_challenge = await provider.challenge_for_authorization_code(
                    client_info, token_request.code
                )
                if expected_challenge is None:
                    raise InvalidRequestError("Invalid authorization code")
                
                # Calculate challenge from verifier
                sha256 = hashlib.sha256(token_request.code_verifier.encode()).digest()
                actual_challenge = base64.urlsafe_b64encode(sha256).decode().rstrip("=")
                
                if actual_challenge != expected_challenge:
                    raise InvalidRequestError("code_verifier does not match the challenge")
                
                # Exchange authorization code for tokens
                tokens = await provider.exchange_authorization_code(client_info, token_request.code)
            
            case RefreshTokenRequest():
                # Parse scopes if provided
                scopes = token_request.scope.split(" ") if token_request.scope else None
                
                # Exchange refresh token for new tokens
                tokens = await provider.exchange_refresh_token(
                    client_info, token_request.refresh_token, scopes
                )

        
        return PydanticJSONResponse(
            content=tokens,
            headers={
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
            }
        )
  
    
    return token_handler