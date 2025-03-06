"""
Client authentication dependency for FastAPI.

Corresponds to TypeScript file: src/server/auth/middleware/clientAuth.ts
"""

import time
from typing import Optional

from fastapi import Request, HTTPException, Depends
from pydantic import BaseModel, ValidationError

from mcp.server.auth.errors import (
    InvalidClientError,
    InvalidRequestError,
    OAuthError,
    ServerError,
)
from mcp.server.auth.provider import OAuthRegisteredClientsStore
from mcp.shared.auth import OAuthClientInformationFull


class ClientAuthRequest(BaseModel):
    """
    Model for client authentication request body.
    
    Corresponds to ClientAuthenticatedRequestSchema in src/server/auth/middleware/clientAuth.ts
    """
    client_id: str
    client_secret: Optional[str] = None


class ClientAuthDependency:
    """
    Dependency that authenticates a client using client_id and client_secret.
    
    This will validate the client credentials and return the client information.
    
    Corresponds to authenticateClient in src/server/auth/middleware/clientAuth.ts
    """
    
    def __init__(self, clients_store: OAuthRegisteredClientsStore):
        """
        Initialize the dependency.
        
        Args:
            clients_store: Store to look up client information
        """
        self.clients_store = clients_store
    
    async def __call__(self, request: Request) -> OAuthClientInformationFull:
        """
        Process the request and authenticate the client.
        
        Args:
            request: FastAPI request
            
        Returns:
            Authenticated client information
            
        Raises:
            HTTPException: If client authentication fails
        """
        try:
            # Parse request body as form data or JSON
            content_type = request.headers.get("Content-Type", "")
            
            if "application/x-www-form-urlencoded" in content_type:
                # Parse form data
                request_data = await request.form()
            elif "application/json" in content_type:
                # Parse JSON data
                request_data = await request.json()
            else:
                raise InvalidRequestError("Unsupported content type")
            
            # Validate client credentials in request
            try:
                # TODO: can I just pass request_data to model_validate without pydantic complaining about extra params?
                client_request = ClientAuthRequest.model_validate({
                    "client_id": request_data.get("client_id"),
                    "client_secret": request_data.get("client_secret"),
                })
            except ValidationError as e:
                raise InvalidRequestError(str(e))
            
            # Look up client information
            client_id = client_request.client_id
            client_secret = client_request.client_secret
            
            client = await self.clients_store.get_client(client_id)
            if not client:
                raise InvalidClientError("Invalid client_id")
            
            # If client has a secret, validate it
            if client.client_secret:
                # Check if client_secret is required but not provided
                if not client_secret:
                    raise InvalidClientError("Client secret is required")
                
                # Check if client_secret matches
                if client.client_secret != client_secret:
                    raise InvalidClientError("Invalid client_secret")
                
                # Check if client_secret has expired
                if (client.client_secret_expires_at and 
                    client.client_secret_expires_at < int(time.time())):
                    raise InvalidClientError("Client secret has expired")
            
            return client
            
        except OAuthError as e:
            status_code = 500 if isinstance(e, ServerError) else 400
            # TODO: make sure we're not leaking anything here
            raise HTTPException(
                status_code=status_code,
                detail=e.to_response_object()
            )