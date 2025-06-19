"""
OAuth2 Authentication implementation for HTTPX using state machine pattern.

Implements authorization code flow with PKCE and automatic token refresh.
"""

import base64
import hashlib
import logging
import secrets
import string
import time
from abc import ABC, abstractmethod
from collections.abc import AsyncGenerator, Awaitable, Callable
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Literal, Protocol, TypeVar
from urllib.parse import urlencode, urljoin, urlparse, urlunparse

import anyio
import httpx
from pydantic import BaseModel, Field, HttpUrl, ValidationError

from mcp.client.streamable_http import MCP_PROTOCOL_VERSION
from mcp.shared.auth import (
    OAuthClientInformationFull,
    OAuthClientMetadata,
    OAuthMetadata,
    OAuthToken,
    ProtectedResourceMetadata,
)
from mcp.types import LATEST_PROTOCOL_VERSION

logger = logging.getLogger(__name__)

# Type variables
T = TypeVar("T", bound="OAuthState")


class OAuthFlowError(Exception):
    """Base exception for OAuth flow errors."""

    pass


class OAuthStateTransitionError(OAuthFlowError):
    """Raised when an invalid state transition is attempted."""

    pass


class OAuthTokenError(OAuthFlowError):
    """Raised when token operations fail."""

    pass


class OAuthRegistrationError(OAuthFlowError):
    """Raised when client registration fails."""

    pass


class PKCEParameters(BaseModel):
    """PKCE (Proof Key for Code Exchange) parameters."""

    code_verifier: str = Field(..., min_length=43, max_length=128)
    code_challenge: str = Field(..., min_length=43, max_length=128)
    code_challenge_method: Literal["S256"] = Field(default="S256")

    @classmethod
    def generate(cls) -> "PKCEParameters":
        """Generate new PKCE parameters."""
        code_verifier = "".join(secrets.choice(string.ascii_letters + string.digits + "-._~") for _ in range(128))
        digest = hashlib.sha256(code_verifier.encode()).digest()
        code_challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")

        return cls(code_verifier=code_verifier, code_challenge=code_challenge)


class AuthorizationContext(BaseModel):
    """Context for authorization flow."""

    state: str = Field(..., min_length=32)
    pkce_params: PKCEParameters
    authorization_url: HttpUrl

    @classmethod
    def create(
        cls, auth_endpoint: str, client_id: str, redirect_uri: str, scope: str | None = None
    ) -> "AuthorizationContext":
        """Create new authorization context."""
        pkce_params = PKCEParameters.generate()
        state = secrets.token_urlsafe(32)

        auth_params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "code_challenge": pkce_params.code_challenge,
            "code_challenge_method": pkce_params.code_challenge_method,
        }

        if scope:
            auth_params["scope"] = scope

        authorization_url = f"{auth_endpoint}?{urlencode(auth_params)}"

        return cls(state=state, pkce_params=pkce_params, authorization_url=HttpUrl(authorization_url))


class TokenStorage(Protocol):
    """Protocol for token storage implementations."""

    async def get_tokens(self) -> OAuthToken | None:
        """Get stored tokens."""
        ...

    async def set_tokens(self, tokens: OAuthToken) -> None:
        """Store tokens."""
        ...

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        """Get stored client information."""
        ...

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        """Store client information."""
        ...


class OAuthStateType(Enum):
    """OAuth flow states."""

    DISCOVERING_PROTECTED_RESOURCE = auto()
    DISCOVERING_OAUTH_METADATA = auto()
    REGISTERING_CLIENT = auto()
    AWAITING_AUTHORIZATION = auto()
    EXCHANGING_TOKEN = auto()
    AUTHENTICATED = auto()
    REFRESHING_TOKEN = auto()
    ERROR = auto()


@dataclass
class StateTransition:
    """Represents a state transition."""

    from_state: OAuthStateType
    to_state: OAuthStateType
    condition: Callable[["OAuthFlowContext"], bool] | None = None
    action: Callable[["OAuthFlowContext"], Awaitable[None]] | None = None


class OAuthState(ABC):
    """Abstract base class for OAuth states."""

    state_type: OAuthStateType

    def __init__(self, context: "OAuthFlowContext"):
        self.context = context

    @abstractmethod
    async def enter(self) -> None:
        """Called when entering this state."""
        pass

    @abstractmethod
    async def execute(self) -> httpx.Request | None:
        """Execute state logic and return next request if needed."""
        pass

    @abstractmethod
    async def handle_response(self, request: httpx.Request, response: httpx.Response) -> OAuthStateType:
        """Handle response and return next state."""
        pass

    @abstractmethod
    def get_valid_transitions(self) -> set[OAuthStateType]:
        """Get valid state transitions from this state."""
        pass


class DiscoveringProtectedResourceState(OAuthState):
    """State for discovering protected resource metadata."""

    state_type = OAuthStateType.DISCOVERING_PROTECTED_RESOURCE

    def __init__(self, context: "OAuthFlowContext"):
        super().__init__(context)

    async def enter(self) -> None:
        logger.debug("Discovering protected resource metadata")

    async def execute(self) -> httpx.Request | None:
        """Build discovery request."""
        auth_base_url = self.context.get_authorization_base_url(self.context.server_url)
        url = urljoin(auth_base_url, "/.well-known/oauth-protected-resource")
        return httpx.Request("GET", url, headers={MCP_PROTOCOL_VERSION: LATEST_PROTOCOL_VERSION})

    async def handle_response(self, request: httpx.Request, response: httpx.Response) -> OAuthStateType:
        """Handle discovery response."""
        if response.status_code == 404:
            # Server doesn't support protected resource metadata (legacy AS server)
            return OAuthStateType.DISCOVERING_OAUTH_METADATA

        if response.status_code == 200:
            try:
                content = await response.aread()
                metadata = ProtectedResourceMetadata.model_validate_json(content)
                self.context.protected_resource_metadata = metadata
                logger.debug(f"Protected resource metadata discovered: {metadata}")

                if metadata.authorization_servers:
                    self.context.auth_server_url = str(metadata.authorization_servers[0])

            except ValidationError as e:
                logger.error(f"Failed to parse protected resource metadata: {e}")

        return OAuthStateType.DISCOVERING_OAUTH_METADATA

    def get_valid_transitions(self) -> set[OAuthStateType]:
        return {OAuthStateType.DISCOVERING_OAUTH_METADATA, OAuthStateType.AUTHENTICATED, OAuthStateType.ERROR}


class DiscoveringOAuthMetadataState(OAuthState):
    """State for discovering OAuth server metadata."""

    state_type = OAuthStateType.DISCOVERING_OAUTH_METADATA

    async def enter(self) -> None:
        logger.debug("Discovering OAuth server metadata")

    async def execute(self) -> httpx.Request | None:
        """Build OAuth metadata discovery request."""
        if self.context.auth_server_url:
            base_url = self.context.get_authorization_base_url(self.context.auth_server_url)
        else:
            base_url = self.context.get_authorization_base_url(self.context.server_url)

        url = urljoin(base_url, "/.well-known/oauth-authorization-server")
        return httpx.Request("GET", url, headers={MCP_PROTOCOL_VERSION: LATEST_PROTOCOL_VERSION})

    async def handle_response(self, request: httpx.Request, response: httpx.Response) -> OAuthStateType:
        """Handle OAuth metadata response."""
        if response.status_code == 404:
            logger.warning("OAuth metadata endpoint not found, proceeding with defaults")
            return OAuthStateType.REGISTERING_CLIENT

        if response.status_code == 200:
            try:
                content = await response.aread()
                metadata = OAuthMetadata.model_validate_json(content)
                self.context.oauth_metadata = metadata
                logger.debug(f"OAuth metadata discovered: {metadata}")

                # Apply default scope if none specified
                if self.context.client_metadata.scope is None and metadata.scopes_supported is not None:
                    self.context.client_metadata.scope = " ".join(metadata.scopes_supported)

            except ValidationError as e:
                logger.error(f"Failed to parse OAuth metadata: {e}")

        return OAuthStateType.REGISTERING_CLIENT

    def get_valid_transitions(self) -> set[OAuthStateType]:
        return {OAuthStateType.REGISTERING_CLIENT, OAuthStateType.ERROR}


class RegisteringClientState(OAuthState):
    """State for registering OAuth client."""

    state_type = OAuthStateType.REGISTERING_CLIENT

    async def enter(self) -> None:
        logger.debug("Registering OAuth client")

    async def execute(self) -> httpx.Request | None:
        """Build registration request or skip if already registered."""
        if self.context.client_info:
            # Already registered, move to authorization
            return None

        if self.context.oauth_metadata and self.context.oauth_metadata.registration_endpoint:
            registration_url = str(self.context.oauth_metadata.registration_endpoint)
        else:
            auth_base_url = self.context.get_authorization_base_url(self.context.server_url)
            registration_url = urljoin(auth_base_url, "/register")

        registration_data = self.context.client_metadata.model_dump(by_alias=True, mode="json", exclude_none=True)

        return httpx.Request(
            "POST", registration_url, json=registration_data, headers={"Content-Type": "application/json"}
        )

    async def handle_response(self, request: httpx.Request, response: httpx.Response) -> OAuthStateType:
        """Handle registration response."""
        if self.context.client_info:
            # Was already registered, trigger authorization
            await self._trigger_authorization()
            return OAuthStateType.AWAITING_AUTHORIZATION

        if response.status_code not in (200, 201):
            raise OAuthRegistrationError(f"Registration failed: {response.status_code} {response.text}")

        try:
            content = await response.aread()
            client_info = OAuthClientInformationFull.model_validate_json(content)
            self.context.client_info = client_info
            await self.context.storage.set_client_info(client_info)
            logger.debug(f"Registration successful: {client_info}")

            await self._trigger_authorization()
            return OAuthStateType.AWAITING_AUTHORIZATION

        except ValidationError as e:
            raise OAuthRegistrationError(f"Invalid registration response: {e}")

    async def _trigger_authorization(self) -> None:
        """Trigger the authorization redirect."""
        if self.context.oauth_metadata and self.context.oauth_metadata.authorization_endpoint:
            auth_endpoint = str(self.context.oauth_metadata.authorization_endpoint)
        else:
            auth_base_url = self.context.get_authorization_base_url(self.context.server_url)
            auth_endpoint = urljoin(auth_base_url, "/authorize")

        if not self.context.client_info:
            raise OAuthFlowError("No client info available for authorization")

        auth_context = AuthorizationContext.create(
            auth_endpoint=auth_endpoint,
            client_id=self.context.client_info.client_id,
            redirect_uri=str(self.context.client_metadata.redirect_uris[0]),
            scope=self.context.client_metadata.scope,
        )

        self.context.authorization_context = auth_context
        await self.context.redirect_handler(str(auth_context.authorization_url))

        # Wait for callback
        auth_code, returned_state = await self.context.callback_handler()

        if returned_state is None or not secrets.compare_digest(returned_state, auth_context.state):
            raise OAuthFlowError(f"State parameter mismatch: {returned_state} != {auth_context.state}")

        if not auth_code:
            raise OAuthFlowError("No authorization code received")

        self.context.authorization_code = auth_code

    def get_valid_transitions(self) -> set[OAuthStateType]:
        return {OAuthStateType.AWAITING_AUTHORIZATION, OAuthStateType.ERROR}


class AwaitingAuthorizationState(OAuthState):
    """State while waiting for user authorization."""

    state_type = OAuthStateType.AWAITING_AUTHORIZATION

    async def enter(self) -> None:
        logger.debug("Awaiting user authorization")

    async def execute(self) -> httpx.Request | None:
        """No request while waiting for authorization."""
        return None

    async def handle_response(self, request: httpx.Request, response: httpx.Response) -> OAuthStateType:
        """Should not receive responses in this state."""
        raise OAuthStateTransitionError("AWAITING_AUTHORIZATION state should not handle responses")

    def get_valid_transitions(self) -> set[OAuthStateType]:
        return {OAuthStateType.EXCHANGING_TOKEN, OAuthStateType.ERROR}


class ExchangingTokenState(OAuthState):
    """State for exchanging authorization code for tokens."""

    state_type = OAuthStateType.EXCHANGING_TOKEN

    async def enter(self) -> None:
        logger.debug("Exchanging authorization code for tokens")

    async def execute(self) -> httpx.Request | None:
        """Build token exchange request."""
        if not self.context.authorization_code or not self.context.client_info:
            raise OAuthFlowError("Missing authorization code or client info")

        if not self.context.authorization_context:
            raise OAuthFlowError("Missing authorization context")

        if self.context.oauth_metadata and self.context.oauth_metadata.token_endpoint:
            token_url = str(self.context.oauth_metadata.token_endpoint)
        else:
            auth_base_url = self.context.get_authorization_base_url(self.context.server_url)
            token_url = urljoin(auth_base_url, "/token")

        token_data = {
            "grant_type": "authorization_code",
            "code": self.context.authorization_code,
            "redirect_uri": str(self.context.client_metadata.redirect_uris[0]),
            "client_id": self.context.client_info.client_id,
            "code_verifier": self.context.authorization_context.pkce_params.code_verifier,
        }

        if self.context.client_info.client_secret:
            token_data["client_secret"] = self.context.client_info.client_secret

        return httpx.Request(
            "POST", token_url, data=token_data, headers={"Content-Type": "application/x-www-form-urlencoded"}
        )

    async def handle_response(self, request: httpx.Request, response: httpx.Response) -> OAuthStateType:
        """Handle token exchange response."""
        if response.status_code != 200:
            try:
                error_data = response.json()
                error_msg = error_data.get("error_description", error_data.get("error", "Unknown error"))
                raise OAuthTokenError(f"Token exchange failed: {error_msg} (HTTP {response.status_code})")
            except Exception:
                raise OAuthTokenError(f"Token exchange failed: {response.status_code} {response.text}")

        try:
            content = await response.aread()
            token_response = OAuthToken.model_validate_json(content)

            await self._validate_token_scopes(token_response)

            self.context.current_tokens = token_response
            self.context.update_token_expiry(token_response)
            await self.context.storage.set_tokens(token_response)

            logger.debug("Token exchange successful")
            return OAuthStateType.AUTHENTICATED

        except ValidationError as e:
            raise OAuthTokenError(f"Invalid token response: {e}")

    async def _validate_token_scopes(self, token_response: OAuthToken) -> None:
        """Validate returned scopes against requested scopes."""
        if not token_response.scope:
            return

        if self.context.client_metadata.scope:
            requested_scopes = set(self.context.client_metadata.scope.split())
            returned_scopes = set(token_response.scope.split())
            unauthorized_scopes = returned_scopes - requested_scopes

            if unauthorized_scopes:
                raise OAuthTokenError(
                    f"Server granted unauthorized scopes: {unauthorized_scopes}. "
                    f"Requested: {requested_scopes}, Returned: {returned_scopes}"
                )
        else:
            logger.debug(
                f"No explicit scopes requested, accepting server-granted "
                f"scopes: {set(token_response.scope.split())}"
            )

    def get_valid_transitions(self) -> set[OAuthStateType]:
        return {OAuthStateType.AUTHENTICATED, OAuthStateType.ERROR}


class AuthenticatedState(OAuthState):
    """State when successfully authenticated."""

    state_type = OAuthStateType.AUTHENTICATED

    async def enter(self) -> None:
        logger.debug("Successfully authenticated")

    async def execute(self) -> httpx.Request | None:
        """No request needed when authenticated."""
        return None

    async def handle_response(self, request: httpx.Request, response: httpx.Response) -> OAuthStateType:
        """Handle 401 responses by refreshing token."""
        if response.status_code == 401:
            if self.context.can_refresh_token():
                return OAuthStateType.REFRESHING_TOKEN
            else:
                # Need to re-authenticate
                self.context.clear_tokens()
                return OAuthStateType.DISCOVERING_PROTECTED_RESOURCE

        return self.state_type

    def get_valid_transitions(self) -> set[OAuthStateType]:
        return {OAuthStateType.REFRESHING_TOKEN, OAuthStateType.DISCOVERING_PROTECTED_RESOURCE, OAuthStateType.ERROR}


class RefreshingTokenState(OAuthState):
    """State for refreshing expired tokens."""

    state_type = OAuthStateType.REFRESHING_TOKEN

    async def enter(self) -> None:
        logger.debug("Refreshing access token")

    async def execute(self) -> httpx.Request | None:
        """Build token refresh request."""
        if not self.context.current_tokens or not self.context.current_tokens.refresh_token:
            raise OAuthTokenError("No refresh token available")

        if not self.context.client_info:
            raise OAuthTokenError("No client info available")

        if self.context.oauth_metadata and self.context.oauth_metadata.token_endpoint:
            token_url = str(self.context.oauth_metadata.token_endpoint)
        else:
            auth_base_url = self.context.get_authorization_base_url(self.context.server_url)
            token_url = urljoin(auth_base_url, "/token")

        refresh_data = {
            "grant_type": "refresh_token",
            "refresh_token": self.context.current_tokens.refresh_token,
            "client_id": self.context.client_info.client_id,
        }

        if self.context.client_info.client_secret:
            refresh_data["client_secret"] = self.context.client_info.client_secret

        return httpx.Request(
            "POST", token_url, data=refresh_data, headers={"Content-Type": "application/x-www-form-urlencoded"}
        )

    async def handle_response(self, request: httpx.Request, response: httpx.Response) -> OAuthStateType:
        """Handle token refresh response."""
        if response.status_code != 200:
            logger.warning(f"Token refresh failed: {response.status_code}")
            self.context.clear_tokens()
            return OAuthStateType.DISCOVERING_PROTECTED_RESOURCE

        try:
            content = await response.aread()
            token_response = OAuthToken.model_validate_json(content)

            self.context.current_tokens = token_response
            self.context.update_token_expiry(token_response)
            await self.context.storage.set_tokens(token_response)

            logger.debug("Token refresh successful")
            return OAuthStateType.AUTHENTICATED

        except ValidationError as e:
            logger.error(f"Invalid refresh response: {e}")
            self.context.clear_tokens()
            return OAuthStateType.DISCOVERING_PROTECTED_RESOURCE

    def get_valid_transitions(self) -> set[OAuthStateType]:
        return {OAuthStateType.AUTHENTICATED, OAuthStateType.DISCOVERING_PROTECTED_RESOURCE, OAuthStateType.ERROR}


class ErrorState(OAuthState):
    """Error state for handling failures."""

    state_type = OAuthStateType.ERROR

    def __init__(self, context: "OAuthFlowContext", error: Exception):
        super().__init__(context)
        self.error = error

    async def enter(self) -> None:
        logger.error(f"OAuth flow error: {self.error}")

    async def execute(self) -> httpx.Request | None:
        """No request in error state."""
        return None

    async def handle_response(self, request: httpx.Request, response: httpx.Response) -> OAuthStateType:
        """Should not receive responses in error state."""
        raise OAuthStateTransitionError("ERROR state should not handle responses")

    def get_valid_transitions(self) -> set[OAuthStateType]:
        return {OAuthStateType.DISCOVERING_PROTECTED_RESOURCE}  # Allow retry


@dataclass
class OAuthFlowContext:
    """Context shared across OAuth flow states."""

    server_url: str
    client_metadata: OAuthClientMetadata
    storage: TokenStorage
    redirect_handler: Callable[[str], Awaitable[None]]
    callback_handler: Callable[[], Awaitable[tuple[str, str | None]]]
    timeout: float = 300.0

    # Discovered metadata
    protected_resource_metadata: ProtectedResourceMetadata | None = None
    oauth_metadata: OAuthMetadata | None = None
    auth_server_url: str | None = None

    # Client registration
    client_info: OAuthClientInformationFull | None = None

    # Authorization flow
    authorization_context: AuthorizationContext | None = None
    authorization_code: str | None = None

    # Token management
    current_tokens: OAuthToken | None = None
    token_expiry_time: float | None = None

    # State machine
    _state_lock: anyio.Lock = field(default_factory=anyio.Lock)

    @property
    def state_lock(self) -> anyio.Lock:
        """Get the state lock for thread-safe access."""
        return self._state_lock

    def get_authorization_base_url(self, server_url: str) -> str:
        """Extract base URL by removing path component."""
        parsed = urlparse(server_url)
        return urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))

    def update_token_expiry(self, token: OAuthToken) -> None:
        """Update token expiry time."""
        if token.expires_in:
            self.token_expiry_time = time.time() + token.expires_in
        else:
            self.token_expiry_time = None

    def is_token_valid(self) -> bool:
        """Check if current token is valid."""
        if not self.current_tokens or not self.current_tokens.access_token:
            return False

        if self.token_expiry_time and time.time() > self.token_expiry_time:
            return False

        return True

    def can_refresh_token(self) -> bool:
        """Check if token can be refreshed."""
        return bool(self.current_tokens and self.current_tokens.refresh_token and self.client_info)

    def clear_tokens(self) -> None:
        """Clear current tokens."""
        self.current_tokens = None
        self.token_expiry_time = None


class OAuthStateMachine:
    """OAuth flow state machine."""

    def __init__(self, context: OAuthFlowContext):
        self.context = context
        self._current_state: OAuthState = DiscoveringProtectedResourceState(context)
        self._state_classes: dict[OAuthStateType, type[OAuthState]] = {
            OAuthStateType.DISCOVERING_PROTECTED_RESOURCE: DiscoveringProtectedResourceState,
            OAuthStateType.DISCOVERING_OAUTH_METADATA: DiscoveringOAuthMetadataState,
            OAuthStateType.REGISTERING_CLIENT: RegisteringClientState,
            OAuthStateType.AWAITING_AUTHORIZATION: AwaitingAuthorizationState,
            OAuthStateType.EXCHANGING_TOKEN: ExchangingTokenState,
            OAuthStateType.AUTHENTICATED: AuthenticatedState,
            OAuthStateType.REFRESHING_TOKEN: RefreshingTokenState,
            OAuthStateType.ERROR: ErrorState,
        }

    @property
    def current_state_type(self) -> OAuthStateType:
        """Get current state type."""
        return self._current_state.state_type

    @property
    def current_state(self) -> OAuthState:
        """Get current state instance."""
        return self._current_state

    async def transition_to(self, new_state_type: OAuthStateType, **kwargs: Any) -> None:
        """Transition to a new state."""
        if new_state_type not in self._current_state.get_valid_transitions():
            raise OAuthStateTransitionError(
                f"Invalid transition from {self._current_state.state_type} to {new_state_type}"
            )

        logger.debug(f"Transitioning from {self._current_state.state_type} to {new_state_type}")

        state_class = self._state_classes[new_state_type]
        self._current_state = state_class(self.context, **kwargs)
        await self._current_state.enter()

    async def execute(self) -> httpx.Request | None:
        """Execute current state logic."""
        return await self._current_state.execute()

    async def handle_response(self, request: httpx.Request, response: httpx.Response) -> OAuthStateType:
        """Handle response and get next state."""
        return await self._current_state.handle_response(request, response)


class OAuthClientProvider(httpx.Auth):
    """
    Authentication for httpx using state machine pattern.
    Handles OAuth flow with automatic client registration and token storage.
    """

    requires_response_body = True

    def __init__(
        self,
        server_url: str,
        client_metadata: OAuthClientMetadata,
        storage: TokenStorage,
        redirect_handler: Callable[[str], Awaitable[None]],
        callback_handler: Callable[[], Awaitable[tuple[str, str | None]]],
        timeout: float = 300.0,
    ):
        """Initialize OAuth2 authentication."""
        self.context = OAuthFlowContext(
            server_url=server_url,
            client_metadata=client_metadata,
            storage=storage,
            redirect_handler=redirect_handler,
            callback_handler=callback_handler,
            timeout=timeout,
        )
        self.state_machine = OAuthStateMachine(self.context)
        self._initialized = False

    async def initialize(self) -> None:
        """Load stored tokens and client info."""
        self.context.current_tokens = await self.context.storage.get_tokens()
        self.context.client_info = await self.context.storage.get_client_info()

        if self.context.is_token_valid():
            await self.state_machine.transition_to(OAuthStateType.AUTHENTICATED)
        # If no valid tokens, stay in DISCOVERING_PROTECTED_RESOURCE (already initialized)

        self._initialized = True

    async def async_auth_flow(self, request: httpx.Request) -> AsyncGenerator[httpx.Request, httpx.Response]:
        """HTTPX auth flow integration using state machine."""
        async with self.context.state_lock:
            if not self._initialized:
                await self.initialize()

            # Execute OAuth flow if not authenticated
            while self.state_machine.current_state_type not in (OAuthStateType.AUTHENTICATED, OAuthStateType.ERROR):
                oauth_request = await self.state_machine.execute()

                if oauth_request:
                    response = yield oauth_request
                    next_state = await self.state_machine.handle_response(oauth_request, response)
                    await self.state_machine.transition_to(next_state)
                else:
                    # Some states don't need requests (e.g., AWAITING_AUTHORIZATION)
                    if self.state_machine.current_state_type == OAuthStateType.AWAITING_AUTHORIZATION:
                        await self.state_machine.transition_to(OAuthStateType.EXCHANGING_TOKEN)
                    elif self.state_machine.current_state_type == OAuthStateType.REGISTERING_CLIENT:
                        await self.state_machine.transition_to(OAuthStateType.AWAITING_AUTHORIZATION)

            # Check for errors
            if self.state_machine.current_state_type == OAuthStateType.ERROR:
                error_state = self.state_machine.current_state
                if isinstance(error_state, ErrorState):
                    raise error_state.error

            # Add authorization header if we have tokens
            if self.context.current_tokens and self.context.current_tokens.access_token:
                request.headers["Authorization"] = f"Bearer {self.context.current_tokens.access_token}"

            # Make the actual request
            response = yield request

            # Handle 401 responses
            if response.status_code == 401:
                next_state = await self.state_machine.handle_response(request, response)

                if next_state == OAuthStateType.REFRESHING_TOKEN:
                    await self.state_machine.transition_to(next_state)

                    # Execute refresh
                    refresh_request = await self.state_machine.execute()
                    if refresh_request:
                        refresh_response = yield refresh_request
                        next_state = await self.state_machine.handle_response(refresh_request, refresh_response)
                        await self.state_machine.transition_to(next_state)

                        # Retry original request with new token
                        if self.context.current_tokens and self.context.current_tokens.access_token:
                            request.headers["Authorization"] = f"Bearer {self.context.current_tokens.access_token}"
                            yield request
                else:
                    # Need full re-authentication
                    await self.state_machine.transition_to(next_state)
                    self._initialized = False
