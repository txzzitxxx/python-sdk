"""
Authentication functionality for MCP client.

This module provides authentication mechanisms for the MCP client to authenticate
with an MCP server. It implements the authentication flow as specified in the MCP
authorization specification.
"""

import base64
import hashlib
import json
import logging
from datetime import datetime, timedelta
from typing import Any, Protocol
from urllib.parse import urlencode, urlparse

import httpx
from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)


class AccessToken(BaseModel):
    """
    Represents an OAuth 2.0 access token with its associated metadata.
    """

    access_token: str
    token_type: str = Field(default="Bearer")
    expires_in: timedelta | None = None
    refresh_token: str | None = None
    scope: str | None = None

    created_at: datetime = Field(default=datetime.now(), exclude=True)

    model_config = ConfigDict(extra="allow")

    def is_expired(self) -> bool:
        """Check if the token is expired."""
        return (
            self.expires_in is not None
            and datetime.now() >= self.created_at + self.expires_in
        )

    @property
    def scopes(self) -> list[str]:
        """Convert scope string to list of scopes."""
        if isinstance(self.scope, list):
            return self.scope
        return self.scope.split() if self.scope else []

    def to_auth_header(self) -> dict[str, str]:
        """Convert token to Authorization header."""

        return {"Authorization": f"{self.token_type} {self.access_token}"}


class AuthConfig(BaseModel):
    """
    Configuration for the MCP client authentication.
    """

    client_id: str
    client_secret: str | None = None
    token_endpoint: str | None = None
    redirect_uri: str | None = None
    scope: str | None = None
    auth_endpoint: str | None = None
    model_config = ConfigDict(extra="allow")


class ClientMetadata(BaseModel):
    """
    OAuth 2.0 Dynamic Client Registration Metadata.

    This model represents the client metadata used when registering a client
    with an OAuth 2.0 server using the Dynamic Client Registration protocol
    as defined in RFC 7591 Section 2.
    """

    redirect_uris: list[AnyHttpUrl] = Field(default_factory=list)
    token_endpoint_auth_method: str | None = None
    grant_types: list[str] | None = None
    response_types: list[str] | None = None
    client_name: str | None = None
    client_uri: AnyHttpUrl | None = None
    logo_uri: AnyHttpUrl | None = None
    scope: str | None = None
    contacts: list[str] | None = None
    tos_uri: AnyHttpUrl | None = None
    policy_uri: AnyHttpUrl | None = None
    jwks_uri: AnyHttpUrl | None = None
    jwks: dict[str, Any] | None = None
    software_id: str | None = None
    software_version: str | None = None

    model_config = ConfigDict(extra="allow")


class DynamicClientRegistration(ClientMetadata):
    """
    Response from OAuth 2.0 Dynamic Client Registration.

    This model represents the response received after registering a client
    with an OAuth 2.0 server using the Dynamic Client Registration protocol
    as defined in RFC 7591.

    Note that we inherit from ClientMetadata, which contains the client metadata,
    since all values sent during the request are also returned in the response,
    as per https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.1
    """

    client_id: str
    client_secret: str | None = None
    client_id_issued_at: int | None = None
    client_secret_expires_at: int | None = None

    model_config = ConfigDict(extra="allow")


class ServerMetadataDiscovery(BaseModel):
    """
    OAuth 2.0 Authorization Server Metadata Discovery Response.

    This model represents the response received from an OAuth 2.0 server's
    metadata discovery endpoint as defined in RFC 8414.
    """

    issuer: AnyHttpUrl
    authorization_endpoint: AnyHttpUrl
    token_endpoint: AnyHttpUrl
    registration_endpoint: AnyHttpUrl | None = None
    scopes_supported: list[str] | None = None
    response_types_supported: list[str]
    response_modes_supported: list[str] | None = None
    grant_types_supported: list[str] | None = None
    token_endpoint_auth_methods_supported: list[str] | None = None
    token_endpoint_auth_signing_alg_values_supported: list[str] | None = None
    service_documentation: AnyHttpUrl | None = None
    revocation_endpoint: AnyHttpUrl | None = None
    revocation_endpoint_auth_methods_supported: list[str] | None = None
    revocation_endpoint_auth_signing_alg_values_supported: list[str] | None = None
    introspection_endpoint: AnyHttpUrl | None = None
    introspection_endpoint_auth_methods_supported: list[str] | None = None
    introspection_endpoint_auth_signing_alg_values_supported: list[str] | None = None
    code_challenge_methods_supported: list[str] | None = None

    model_config = ConfigDict(extra="allow")


class TokenManager:
    """
    Manages OAuth tokens for MCP client, handling token refresh and expiration.
    """

    def __init__(self, config: AuthConfig):
        self.config = config
        self.token: AccessToken | None = None

    @property
    def is_authenticated(self) -> bool:
        """Check if the client is authenticated with a valid token."""
        return self.token is not None and not self.token.is_expired

    async def refresh_token_if_needed(self) -> bool:
        """
        Refresh the token if it's expired or close to expiration.

        Returns:
            bool: True if token was refreshed, False otherwise
        """
        if not self.token or not self.token.refresh_token:
            return False

        if self.token.is_expired():
            await self.refresh()
            return True

        return False

    async def refresh(self) -> AccessToken | None:
        """
        Refresh the access token using the refresh token.

        Returns:
            AccessToken | None: The new token if successful, None otherwise
        """
        if (
            not self.token
            or not self.token.refresh_token
            or not self.config.token_endpoint
        ):
            return None

        data = {
            "grant_type": "refresh_token",
            "refresh_token": self.token.refresh_token,
            "client_id": self.config.client_id,
        }

        # Add client secret if available
        if self.config.client_secret:
            data["client_secret"] = self.config.client_secret

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.config.token_endpoint,
                    data=data,
                    headers=headers,
                )
                response.raise_for_status()
                token_data = response.json()

                # Create and store the token
                token = AccessToken(**token_data)

                # If the response didn't include a refresh token, keep the old one
                if not token.refresh_token and self._token.refresh_token:
                    token.refresh_token = self._token.refresh_token

                self._token = token
                return token

        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error during token refresh: {e.response.status_code}")
            if e.response.content:
                try:
                    error_data = json.loads(e.response.content)
                    logger.error(f"Error details: {error_data}")
                except json.JSONDecodeError:
                    logger.error(f"Error content: {e.response.content}")
            return None

        except httpx.RequestError as e:
            logger.error(f"Request error during token refresh: {e}")
            return None

        except Exception as e:
            logger.error(f"Unexpected error during token refresh: {e}")
            return None

    async def authenticate_with_client_credentials(self) -> AccessToken | None:
        """
        Authenticate using client credentials flow.

        Returns:
            AccessToken | None: The access token if successful, None otherwise
        """
        if not self.config.token_endpoint or not self.config.client_id:
            logger.error("Token endpoint or client ID not configured")
            return None

        data = {
            "grant_type": "client_credentials",
            "client_id": self.config.client_id,
        }

        # Add client secret if available
        if self.config.client_secret:
            data["client_secret"] = self.config.client_secret

        # Add scope if available
        if self.config.scope:
            data["scope"] = self.config.scope

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.config.token_endpoint,
                    data=data,
                    headers=headers,
                )
                response.raise_for_status()
                token_data = response.json()

                # Create and store the token
                token = AccessToken(**token_data)
                self._token = token
                return token

        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error during authentication: {e.response.status_code}")
            if e.response.content:
                try:
                    error_data = json.loads(e.response.content)
                    logger.error(f"Error details: {error_data}")
                except json.JSONDecodeError:
                    logger.error(f"Error content: {e.response.content}")
            return None

        except httpx.RequestError as e:
            logger.error(f"Request error during authentication: {e}")
            return None

        except Exception as e:
            logger.error(f"Unexpected error during authentication: {e}")
            return None


class AuthSession:
    """
    Client for handling authentication with an MCP server.

    This client provides methods for authenticating with an MCP server using
    various OAuth 2.0 flows and managing the resulting tokens.
    """

    def __init__(self, config: AuthConfig):
        """
        Initialize the authentication client with the given configuration.

        Args:
            config: Authentication configuration
        """
        self.config = config
        self.token_manager: TokenManager = TokenManager(config)

    async def initialize(self) -> None:
        """
        Initialize the client and prepare it for authentication.
        """
        if self.token_manager is None:
            self.token_manager = TokenManager(self.config)

    async def authenticate_with_client_credentials(self) -> AccessToken | None:
        """
        Authenticate using the client credentials flow.

        This flow is typically used for machine-to-machine authentication
        where the client is acting on its own behalf, not on behalf of a user.

        Returns:
            AccessToken | None: The access token if successful, None otherwise
        """
        await self.initialize()
        return await self.token_manager.authenticate_with_client_credentials()

    async def get_auth_headers(self) -> dict[str, str]:
        """
        Get the authentication headers for API requests.

        This method will refresh the token if needed before returning headers.

        Returns:
            dict[str, str]: Authentication headers
        """
        await self.initialize()
        await self.token_manager.refresh_token_if_needed()

        if not self.token_manager.token:
            return {}

        return self.token_manager.token.to_auth_header()

    @property
    def is_authenticated(self) -> bool:
        """Check if the client is authenticated with a valid token."""
        if self.token_manager is None:
            return False
        return self.token_manager.is_authenticated


class OAuthClientProvider(Protocol):
    @property
    def client_metadata(self) -> ClientMetadata: ...

    @property
    def redirect_url(self) -> AnyHttpUrl: ...

    async def open_user_agent(self, url: AnyHttpUrl) -> None:
        """
        Opens the user agent to the given URL.
        """
        ...

    async def client_registration(
        self, endpoint: AnyHttpUrl
    ) -> DynamicClientRegistration | None:
        """
        Loads the client registration for the given endpoint.
        """
        ...

    async def store_client_registration(
        self, endpoint: AnyHttpUrl, metadata: DynamicClientRegistration
    ) -> None:
        """
        Stores the client registration to be retreived for the next session
        """
        ...

    def code_verifier(self) -> str:
        """
        Loads the PKCE code verifier for the current session.
        See https://www.rfc-editor.org/rfc/rfc7636.html#section-4.1
        """
        ...

    async def token(self) -> AccessToken | None:
        """
        Loads the token for the current session.
        """
        ...

    async def store_token(self, token: AccessToken) -> None:
        """
        Stores the token to be retreived for the next session
        """
        ...


class NotFoundError(Exception):
    """Exception raised when a resource or endpoint is not found."""

    pass


class RegistrationFailedError(Exception):
    """Exception raised when client registration fails."""

    pass


class GrantNotSupported(Exception):
    """Exception raised when a grant type is not supported."""

    pass


class OAuthClient:
    WELL_KNOWN = "/.well-known/oauth-authorization-server"
    GRANT_TYPE: str = "authorization_code"

    def __init__(
        self,
        server_url: AnyHttpUrl,
        provider: OAuthClientProvider,
        scope: str | None = None,
    ):
        self.server_url = server_url
        self.http_client = httpx.AsyncClient()
        self.provider = provider
        self.scope = scope

    @property
    def discovery_url(self) -> AnyHttpUrl:
        base_url = str(self.server_url).rstrip("/")
        parsed_url = urlparse(base_url)
        # HTTPS is required by RFC 8414
        discovery_url = f"https://{parsed_url.netloc}{self.WELL_KNOWN}"
        return AnyHttpUrl(discovery_url)

    async def _obtain_client(
        self, metadata: ServerMetadataDiscovery
    ) -> DynamicClientRegistration:
        """
        Obtain a client by either reading it from the OAuthProvider or registering it.
        """
        if metadata.registration_endpoint is None:
            raise NotFoundError("Registration endpoint not found")

        if registration := await self.provider.client_registration(metadata.issuer):
            return registration
        else:
            registration = await self.dynamic_client_registration(
                self.provider.client_metadata, metadata.registration_endpoint
            )
            if registration is None:
                raise RegistrationFailedError(
                    f"Registration at {metadata.registration_endpoint} failed"
                )

            await self.provider.store_client_registration(metadata.issuer, registration)
            return registration

    def default_metadata(self) -> ServerMetadataDiscovery:
        """
        Returns default endpoints as specified in
        https://spec.modelcontextprotocol.io/specification/draft/basic/authorization/
        for the server.
        """
        base_url = AnyHttpUrl(str(self.server_url).rstrip("/"))
        return ServerMetadataDiscovery(
            issuer=base_url,
            authorization_endpoint=AnyHttpUrl(f"{base_url}/authorize"),
            token_endpoint=AnyHttpUrl(f"{base_url}/token"),
            registration_endpoint=AnyHttpUrl(f"{base_url}/register"),
            response_types_supported=["code"],
            grant_types_supported=["authorization_code", "refresh_token"],
            token_endpoint_auth_methods_supported=["client_secret_post"],
        )

    async def discover_auth_metadata(self) -> ServerMetadataDiscovery | None:
        """
        Use RFC 8414 to discover the authorization server metadata.
        """
        try:
            response = await self.http_client.get(str(self.discovery_url))
            if response.status_code == 404:
                return None
            response.raise_for_status()
            json_data = await response.aread()
            return ServerMetadataDiscovery.model_validate_json(json_data)
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP status: {e}")
            raise
        except Exception as e:
            logger.error(f"Error during auth metadata discovery: {e}")
            raise

    async def dynamic_client_registration(
        self, client_metadata: ClientMetadata, registration_endpoint: AnyHttpUrl
    ) -> DynamicClientRegistration | None:
        """
        Register a client dynamically with an OAuth 2.0 authorization server
        following RFC 7591.
        """
        headers = {"Content-Type": "application/json", "Accept": "application/json"}

        try:
            response = await self.http_client.post(
                str(registration_endpoint),
                json=client_metadata.model_dump(exclude_none=True),
                headers=headers,
            )
            if response.status_code == 404:
                logger.error(
                    f"Registration endpoint not found at {registration_endpoint}"
                )
                return None
            response.raise_for_status()
            client_data = await response.aread()
            return DynamicClientRegistration.model_validate_json(client_data)
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error in client registration: {e.response.status_code}")
            if e.response.content:
                try:
                    error_data = json.loads(e.response.content)
                    logger.error(f"Error details: {error_data}")
                except json.JSONDecodeError:
                    logger.error(f"Error content: {e.response.content}")
        except Exception as e:
            logger.error(f"Unexpected error during registration: {e}")

        return None

    async def exchange_authorization(
        self,
        metadata: ServerMetadataDiscovery,
        registration: DynamicClientRegistration,
        code_verifier: str,
        authorization_code: str,
    ) -> AccessToken:
        """Exchange an authorization code for an access token using OAuth 2.1 with PKCE.

        Args:
            registration: The client registration information
            code_verifier: The PKCE code verifier used to generate the code challenge
            authorization_code: The authorization code received from the authorization
                server

        Returns:
            AccessToken: The resulting access token

        Raises:
            GrantNotSupported: If the grant type is not supported
            httpx.HTTPStatusError: If the token endpoint request fails
        """
        if self.GRANT_TYPE not in (registration.grant_types or []):
            raise GrantNotSupported(f"Grant type {self.GRANT_TYPE} not supported")

        code_verifier = self.provider.code_verifier()
        # Get token endpoint from server metadata or use default
        token_endpoint = str(metadata.token_endpoint)

        # Prepare token request parameters
        data = {
            "grant_type": self.GRANT_TYPE,
            "code": authorization_code,
            "redirect_uri": str(self.provider.redirect_url),
            "client_id": registration.client_id,
            "code_verifier": code_verifier,
        }

        # Add client secret if available (optional in OAuth 2.1)
        if registration.client_secret:
            data["client_secret"] = registration.client_secret

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }

        try:
            response = await self.http_client.post(
                token_endpoint, data=data, headers=headers
            )
            response.raise_for_status()
            token_data = response.json()

            # Create and return the token
            return AccessToken(**token_data)

        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error during token exchange: {e.response.status_code}")
            if e.response.content:
                try:
                    error_data = json.loads(e.response.content)
                    logger.error(f"Error details: {error_data}")
                except json.JSONDecodeError:
                    logger.error(f"Error content: {e.response.content}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during token exchange: {e}")
            raise

    async def auth(self, authorization_code: str, code_verifier: str) -> AccessToken:
        """
        Complete the OAuth 2.1 authorization flow by exchanging authorization code
        for tokens.

        Args:
            authorization_code: The authorization code received from the authorization
                server
            code_verifier: The PKCE code verifier used to generate the code challenge

        Returns:
            AccessToken: The resulting access token
        """
        metadata = await self.discover_auth_metadata() or self.default_metadata()
        registration = await self._obtain_client(metadata)

        code_verifier = self.provider.code_verifier()

        authorization_url = self.get_authorization_url(
            metadata.authorization_endpoint,
            self.provider.redirect_url,
            registration.client_id,
            code_verifier,
            self.scope,
        )

        await self.provider.open_user_agent(AnyHttpUrl(authorization_url))

        return await self.exchange_authorization(
            metadata, registration, code_verifier, authorization_code
        )

    def get_authorization_url(
        self,
        authorization_endpoint: AnyHttpUrl,
        redirect_uri: AnyHttpUrl,
        client_id: str,
        code_verifier: str,
        scope: str | None = None,
    ) -> AnyHttpUrl:
        """Generate an OAuth 2.1 authorization URL for the user agent.

        This method generates a URL that the user agent (browser) should visit to
        authenticate the user and authorize the application. It includes PKCE
        (Proof Key for Code Exchange) for enhanced security as required by OAuth 2.1.
        """
        # Create a custom verifier for this authorization request
        code_verifier = self.provider.code_verifier()

        # Generate code challenge from verifier using SHA-256
        code_challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
            .decode()
            .rstrip("=")
        )

        # Build authorization URL with necessary parameters
        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": str(redirect_uri),
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }

        # Add scope if provided or use the one from registration
        if scope:
            params["scope"] = scope

        # Construct the full authorization URL
        return AnyHttpUrl(f"{authorization_endpoint}?{urlencode(params)}")
