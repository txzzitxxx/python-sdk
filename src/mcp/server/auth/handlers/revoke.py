"""
Handler for OAuth 2.0 Token Revocation.

Corresponds to TypeScript file: src/server/auth/handlers/revoke.ts
"""

from typing import Any, Callable, Dict, Optional

from fastapi import Request, Response
from pydantic import ValidationError
from starlette.responses import JSONResponse, Response as StarletteResponse

from mcp.server.auth.errors import (
    InvalidRequestError,
    ServerError,
    OAuthError,
)
from mcp.server.auth.provider import OAuthServerProvider
from mcp.shared.auth import OAuthClientInformationFull, OAuthTokenRevocationRequest


def create_revocation_handler(provider: OAuthServerProvider) -> Callable:
    """
    Create a handler for OAuth 2.0 Token Revocation.
    
    Corresponds to revocationHandler in src/server/auth/handlers/revoke.ts
    
    Args:
        provider: The OAuth server provider
        
    Returns:
        A FastAPI route handler function
    """
    
    async def revocation_handler(request: Request, client_auth: OAuthClientInformationFull) -> Response:
        """
        Handler for the OAuth 2.0 Token Revocation endpoint.
        """
        # Validate revocation request
        try:
            revocation_request = OAuthTokenRevocationRequest.model_validate_json(await request.body())
        except ValidationError as e:
            raise InvalidRequestError(str(e))
        
        # Revoke token
        if provider.revoke_token:
            await provider.revoke_token(client_auth, revocation_request)
        
        # Return successful empty response
        return StarletteResponse(
            status_code=200,
            headers={
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
            }
        )
    
    return revocation_handler