"""
Client authentication middleware for ASGI applications.

Corresponds to TypeScript file: src/server/auth/middleware/clientAuth.ts
"""

import time
from typing import Any, Callable

from starlette.requests import Request
from starlette.exceptions import HTTPException
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
    client_secret: str | None = None


class ClientAuthenticator:
    """
    Dependency that authenticates a client using client_id and client_secret.
    
    This is a callable that can be used to validate client credentials in a request.
    
    Corresponds to authenticateClient in src/server/auth/middleware/clientAuth.ts
    """
    
    def __init__(self, clients_store: OAuthRegisteredClientsStore):
        """
        Initialize the dependency.
        
        Args:
            clients_store: Store to look up client information
        """
        self.clients_store = clients_store
    
    async def __call__(self, request: ClientAuthRequest) -> OAuthClientInformationFull:
        # Look up client information
        client = await self.clients_store.get_client(request.client_id)
        if not client:
            raise InvalidClientError("Invalid client_id")
        
        # If client from the store expects a secret, validate that the request provides that secret
        if client.client_secret:
            if not request.client_secret:
                raise InvalidClientError("Client secret is required")
            
            if client.client_secret != request.client_secret:
                raise InvalidClientError("Invalid client_secret")
            
            if (client.client_secret_expires_at and 
                client.client_secret_expires_at < int(time.time())):
                raise InvalidClientError("Client secret has expired")
        
        return client
    


class ClientAuthMiddleware:
    """
    Middleware that authenticates clients using client_id and client_secret.
    
    This middleware will validate client credentials and store client information
    in the request state.
    """
    
    def __init__(
        self,
        app: Any,
        clients_store: OAuthRegisteredClientsStore,
    ):
        """
        Initialize the middleware.
        
        Args:
            app: ASGI application
            clients_store: Store for client information
        """
        self.app = app
        self.client_auth = ClientAuthenticator(clients_store)
        
    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        """
        Process the request and authenticate the client.
        
        Args:
            scope: ASGI scope
            receive: ASGI receive function
            send: ASGI send function
        """
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
            
        # Create a request object to access the request data
        request = Request(scope, receive=receive)
        
        # Add client authentication to the request
        try:
            client = await self.client_auth(ClientAuthRequest.model_validate(request))
            # Store the client in the request state
            request.state.client = client
        except HTTPException:
            # Continue without authentication
            pass
            
        # Continue processing the request
        await self.app(scope, receive, send)