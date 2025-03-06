"""
Handler for OAuth 2.0 Token endpoint.

Corresponds to TypeScript file: src/server/auth/handlers/token.ts
"""

import base64
import hashlib
import json
from typing import Any, Callable, Dict, List, Optional, Union

from fastapi import Request, Response
from pydantic import BaseModel, Field, ValidationError
from starlette.responses import JSONResponse

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
from mcp.server.auth.middleware.client_auth import ClientAuthDependency

class AuthorizationCodeRequest(BaseModel):
    """
    Model for the authorization code grant request parameters.
    
    Corresponds to AuthorizationCodeExchangeSchema in src/server/auth/handlers/token.ts
    """
    grant_type: str = Field(..., description="Must be 'authorization_code'")
    code: str = Field(..., description="The authorization code")
    code_verifier: str = Field(..., description="PKCE code verifier")
    
    class Config:
        extra = "ignore"


class RefreshTokenRequest(BaseModel):
    """
    Model for the refresh token grant request parameters.
    
    Corresponds to RefreshTokenExchangeSchema in src/server/auth/handlers/token.ts
    """
    grant_type: str = Field(..., description="Must be 'refresh_token'")
    refresh_token: str = Field(..., description="The refresh token")
    scope: Optional[str] = Field(None, description="Optional scope parameter")
    
    class Config:
        extra = "ignore"


def create_token_handler(provider: OAuthServerProvider) -> Callable:
    """
    Create a handler for the OAuth 2.0 Token endpoint.
    
    Corresponds to tokenHandler in src/server/auth/handlers/token.ts
    
    Args:
        provider: The OAuth server provider
        
    Returns:
        A FastAPI route handler function
    """
    
    async def token_handler(request: Request, client_auth: OAuthClientInformationFull) -> Response:
        """
        Handler for the OAuth 2.0 Token endpoint.
        
        Args:
            request: The FastAPI request
            
        Returns:
            JSON response with tokens or error
        """
        params = json.loads(await request.body())

        
        # Check grant_type first to determine which validation model to use
        if "grant_type" not in params:
            raise InvalidRequestError("Missing required parameter: grant_type")
        grant_type = params["grant_type"]
        
        tokens: OAuthTokens
        
        if grant_type == "authorization_code":
            # Validate authorization code parameters
            try:
                code_request = AuthorizationCodeRequest.model_validate(params)
            except ValidationError as e:
                raise InvalidRequestError(str(e))
            
            # Verify PKCE code verifier
            expected_challenge = await provider.challenge_for_authorization_code(
                client_auth, code_request.code
            )
            if expected_challenge is None:
                raise InvalidRequestError("Invalid authorization code")
            
            # Calculate challenge from verifier
            sha256 = hashlib.sha256(code_request.code_verifier.encode()).digest()
            actual_challenge = base64.urlsafe_b64encode(sha256).decode().rstrip("=")
            
            if actual_challenge != expected_challenge:
                raise InvalidRequestError("code_verifier does not match the challenge")
            
            # Exchange authorization code for tokens
            tokens = await provider.exchange_authorization_code(client_auth, code_request.code)
            
        elif grant_type == "refresh_token":
            # Validate refresh token parameters
            try:
                refresh_request = RefreshTokenRequest.model_validate(params)
            except ValidationError as e:
                raise InvalidRequestError(str(e))
            
            # Parse scopes if provided
            scopes = refresh_request.scope.split(" ") if refresh_request.scope else None
            
            # Exchange refresh token for new tokens
            tokens = await provider.exchange_refresh_token(
                client_auth, refresh_request.refresh_token, scopes
            )
            
        else:
            raise InvalidRequestError(
                f"Unsupported grant_type: {grant_type}"
            )
        
        return JSONResponse(
            content=tokens,
            headers={
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
            }
        )
  
    
    return token_handler