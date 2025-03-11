"""
OAuth server provider interfaces for MCP authorization.

Corresponds to TypeScript file: src/server/auth/provider.ts
"""

from typing import Any, Protocol
from pydantic import AnyHttpUrl, BaseModel
from starlette.responses import Response

from mcp.shared.auth import OAuthClientInformationFull, OAuthTokenRevocationRequest, OAuthTokens
from mcp.server.auth.types import AuthInfo


class AuthorizationParams(BaseModel):
    """
    Parameters for the authorization flow.
    
    Corresponds to AuthorizationParams in src/server/auth/provider.ts
    """
    state: str | None = None
    scopes: list[str] | None = None
    code_challenge: str
    redirect_uri: AnyHttpUrl


class OAuthRegisteredClientsStore(Protocol):
    """
    Interface for storing and retrieving registered OAuth clients.
    
    Corresponds to OAuthRegisteredClientsStore in src/server/auth/clients.ts
    """
    
    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        """
        Retrieves client information by client ID.
        
        Args:
            client_id: The ID of the client to retrieve.
            
        Returns:
            The client information, or None if the client does not exist.
        """
        ...
    
    async def register_client(self, 
                             client_info: OAuthClientInformationFull
                             ) -> OAuthClientInformationFull | None:
        """
        Registers a new client and returns client information.
        
        Args:
            metadata: The client metadata to register.
            
        Returns:
            The client information, or None if registration failed.
        """
        ...


class OAuthServerProvider(Protocol):
    """
    Implements an end-to-end OAuth server.
    
    Corresponds to OAuthServerProvider in src/server/auth/provider.ts
    """
    
    @property
    def clients_store(self) -> OAuthRegisteredClientsStore:
        """
        A store used to read information about registered OAuth clients.
        """
        ...
    
    # TODO: do we really want to be putting the response in this method?
    async def authorize(self, 
                       client: OAuthClientInformationFull, 
                       params: AuthorizationParams, 
                       response: Response) -> None:
        """
        Begins the authorization flow, which can be implemented by this server or via redirection.
        Must eventually issue a redirect with authorization response or error to the given redirect URI.
        
        Args:
            client: The client requesting authorization.
            params: Parameters for the authorization request.
            response: The response object to write to.
        """
        ...
    
    async def challenge_for_authorization_code(self, 
                                             client: OAuthClientInformationFull, 
                                             authorization_code: str) -> str | None:
        """
        Returns the code_challenge that was used when the indicated authorization began.
        
        Args:
            client: The client that requested the authorization code.
            authorization_code: The authorization code to get the challenge for.
            
        Returns:
            The code challenge that was used when the authorization began.
        """
        ...
    
    async def exchange_authorization_code(self, 
                                        client: OAuthClientInformationFull, 
                                        authorization_code: str) -> OAuthTokens:
        """
        Exchanges an authorization code for an access token.
        
        Args:
            client: The client exchanging the authorization code.
            authorization_code: The authorization code to exchange.
            
        Returns:
            The access and refresh tokens.
        """
        ...
    
    async def exchange_refresh_token(self, 
                                   client: OAuthClientInformationFull, 
                                   refresh_token: str, 
                                   scopes: list[str] | None = None) -> OAuthTokens:
        """
        Exchanges a refresh token for an access token.
        
        Args:
            client: The client exchanging the refresh token.
            refresh_token: The refresh token to exchange.
            scopes: Optional scopes to request with the new access token.
            
        Returns:
            The new access and refresh tokens.
        """
        ...

    # TODO: consider methods to generate refresh tokens and access tokens
    
    async def verify_access_token(self, token: str) -> AuthInfo:
        """
        Verifies an access token and returns information about it.
        
        Args:
            token: The access token to verify.
            
        Returns:
            Information about the verified token.
        """
        ...
    
    async def revoke_token(self, 
                         client: OAuthClientInformationFull, 
                         request: OAuthTokenRevocationRequest) -> None:
        """
        Revokes an access or refresh token.
        
        If the given token is invalid or already revoked, this method should do nothing.
        
        Args:
            client: The client revoking the token.
            request: The token revocation request.
        """
        ...