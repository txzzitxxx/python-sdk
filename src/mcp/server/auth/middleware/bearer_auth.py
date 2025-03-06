"""
Bearer token authentication dependency for FastAPI.

Corresponds to TypeScript file: src/server/auth/middleware/bearerAuth.ts
"""

import time
from typing import List, Optional

from fastapi import Request, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from mcp.server.auth.errors import InsufficientScopeError, InvalidTokenError, OAuthError
from mcp.server.auth.provider import OAuthServerProvider
from mcp.server.auth.types import AuthInfo


class BearerAuthDependency:
    """
    Dependency that requires a valid Bearer token in the Authorization header.
    
    This will validate the token with the auth provider and return the resulting 
    auth info.
    
    Corresponds to requireBearerAuth in src/server/auth/middleware/bearerAuth.ts
    """
    
    def __init__(
        self,
        provider: OAuthServerProvider,
        required_scopes: Optional[List[str]] = None
    ):
        """
        Initialize the dependency.
        
        Args:
            provider: Authentication provider to validate tokens
            required_scopes: Optional list of scopes that the token must have
        """
        self.provider = provider
        self.required_scopes = required_scopes or []
        self.bearer_scheme = HTTPBearer()
    
    async def __call__(self, request: Request) -> AuthInfo:
        """
        Process the request and validate the bearer token.
        
        Args:
            request: FastAPI request
            
        Returns:
            Authenticated auth info
            
        Raises:
            HTTPException: If token validation fails
        """
        try:
            # Extract and validate the authorization header using FastAPI's built-in scheme
            credentials: HTTPAuthorizationCredentials = await self.bearer_scheme(request)
            token = credentials.credentials
            
            # Validate the token with the provider
            auth_info: AuthInfo = await self.provider.verify_access_token(token)
            
            # Check if the token has all required scopes
            if self.required_scopes:
                has_all_scopes = all(scope in auth_info.scopes for scope in self.required_scopes)
                if not has_all_scopes:
                    raise InsufficientScopeError("Insufficient scope")
            
            # Check if the token is expired
            if auth_info.expires_at and auth_info.expires_at < int(time.time()):
                raise InvalidTokenError("Token has expired")
            
            return auth_info
            
        except InvalidTokenError as e:
            # Return a 401 Unauthorized response with appropriate headers
            headers = {"WWW-Authenticate": f'Bearer error="{e.error_code}", error_description="{str(e)}"'}
            raise HTTPException(
                status_code=401,
                detail=e.to_response_object(),
                headers=headers
            )
        except InsufficientScopeError as e:
            # Return a 403 Forbidden response with appropriate headers
            headers = {"WWW-Authenticate": f'Bearer error="{e.error_code}", error_description="{str(e)}"'}
            raise HTTPException(
                status_code=403,
                detail=e.to_response_object(),
                headers=headers
            )
        except OAuthError as e:
            # Return a 400 Bad Request response for other OAuth errors
            raise HTTPException(
                status_code=400,
                detail=e.to_response_object()
            )