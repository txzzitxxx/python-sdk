"""
OAuth server provider interfaces for MCP authorization.

Corresponds to TypeScript file: src/server/auth/provider.ts
"""

from typing import List, Literal, Optional, Protocol

from pydantic import AnyHttpUrl, BaseModel

from mcp.server.auth.types import AuthInfo
from mcp.shared.auth import (
    OAuthClientInformationFull,
    OAuthTokens,
)


class AuthorizationParams(BaseModel):
    """
    Parameters for the authorization flow.

    Corresponds to AuthorizationParams in src/server/auth/provider.ts
    """

    state: Optional[str] = None
    scopes: Optional[List[str]] = None
    code_challenge: str
    redirect_uri: AnyHttpUrl

class AuthorizationCodeMeta(BaseModel):
    issued_at: float
    client_id: str
    code_challenge: str
    redirect_uri: AnyHttpUrl
class OAuthTokenRevocationRequest(BaseModel):
    """
    # See https://datatracker.ietf.org/doc/html/rfc7009#section-2.1
    """

    token: str
    token_type_hint: Optional[Literal["access_token", "refresh_token"]] = None

class OAuthRegisteredClientsStore(Protocol):
    """
    Interface for storing and retrieving registered OAuth clients.

    Corresponds to OAuthRegisteredClientsStore in src/server/auth/clients.ts
    """

    async def get_client(self, client_id: str) -> Optional[OAuthClientInformationFull]:
        """
        Retrieves client information by client ID.

        Args:
            client_id: The ID of the client to retrieve.

        Returns:
            The client information, or None if the client does not exist.
        """
        ...

    async def register_client(
        self, client_info: OAuthClientInformationFull
    ) -> Optional[OAuthClientInformationFull]:
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

    async def create_authorization_code(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        """
        Generates and stores an authorization code as part of completing the /authorize
        OAuth step.

        Implementations SHOULD generate an authorization code with at least 160 bits of
        entropy,
        and MUST generate an authorization code with at least 128 bits of entropy.
        See https://datatracker.ietf.org/doc/html/rfc6749#section-10.10.
        """
        ...

    async def load_authorization_code_metadata(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCodeMeta | None:
        """
        Loads metadata for the authorization code challenge.

        Args:
            client: The client that requested the authorization code.
            authorization_code: The authorization code to get the challenge for.

        Returns:
            The code challenge that was used when the authorization began.
        """
        ...

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> OAuthTokens:
        """
        Exchanges an authorization code for an access token.

        Args:
            client: The client exchanging the authorization code.
            authorization_code: The authorization code to exchange.

        Returns:
            The access and refresh tokens.
        """
        ...

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: str,
        scopes: Optional[List[str]] = None,
    ) -> OAuthTokens:
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

    async def revoke_token(
        self, client: OAuthClientInformationFull, request: OAuthTokenRevocationRequest
    ) -> None:
        """
        Revokes an access or refresh token.

        If the given token is invalid or already revoked, this method should do nothing.

        Args:
            client: The client revoking the token.
            request: The token revocation request.
        """
        ...
