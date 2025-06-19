"""
Tests for OAuth client authentication implementation.
"""

import time
from unittest.mock import AsyncMock, Mock

import pytest
from pydantic import AnyHttpUrl, AnyUrl

from mcp.client.auth import OAuthClientProvider, OAuthStateType, PKCEParameters
from mcp.shared.auth import (
    OAuthClientInformationFull,
    OAuthClientMetadata,
    OAuthToken,
)


class MockTokenStorage:
    """Mock token storage for testing."""

    def __init__(self):
        self._tokens: OAuthToken | None = None
        self._client_info: OAuthClientInformationFull | None = None

    async def get_tokens(self) -> OAuthToken | None:
        return self._tokens

    async def set_tokens(self, tokens: OAuthToken) -> None:
        self._tokens = tokens

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        return self._client_info

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        self._client_info = client_info


@pytest.fixture
def mock_storage():
    return MockTokenStorage()


@pytest.fixture
def client_metadata():
    return OAuthClientMetadata(
        client_name="Test Client",
        client_uri=AnyHttpUrl("https://example.com"),
        redirect_uris=[AnyUrl("http://localhost:3030/callback")],
        scope="read write",
        token_endpoint_auth_method="client_secret_post",
    )


@pytest.fixture
def valid_tokens():
    return OAuthToken(
        access_token="valid_access_token",
        token_type="Bearer",
        expires_in=3600,
        refresh_token="valid_refresh_token",
        scope="read write",
    )


@pytest.fixture
def oauth_provider(client_metadata, mock_storage):
    return OAuthClientProvider(
        server_url="https://api.example.com/v1/mcp",
        client_metadata=client_metadata,
        storage=mock_storage,
        redirect_handler=AsyncMock(),
        callback_handler=AsyncMock(return_value=("auth_code", None)),
    )


class TestOAuthClientAuth:
    """Test OAuth client authentication."""

    def test_pkce_parameters_generation(self):
        """Test PKCEParameters.generate() creates valid PKCE params."""
        pkce = PKCEParameters.generate()

        # Check code verifier format
        assert len(pkce.code_verifier) == 128
        allowed_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
        assert set(pkce.code_verifier) <= allowed_chars

        # Check code challenge format
        assert len(pkce.code_challenge) >= 43
        assert "=" not in pkce.code_challenge  # Base64url without padding
        assert "+" not in pkce.code_challenge
        assert "/" not in pkce.code_challenge

        # Check method
        assert pkce.code_challenge_method == "S256"

        # Test uniqueness
        pkce2 = PKCEParameters.generate()
        assert pkce.code_verifier != pkce2.code_verifier
        assert pkce.code_challenge != pkce2.code_challenge

    @pytest.mark.anyio
    async def test_oauth_provider_initialization(self, oauth_provider, client_metadata, mock_storage):
        """Test OAuthClientProvider basic setup."""
        assert oauth_provider.context.server_url == "https://api.example.com/v1/mcp"
        assert oauth_provider.context.client_metadata == client_metadata
        assert oauth_provider.context.storage == mock_storage
        assert oauth_provider.context.timeout == 300.0
        assert oauth_provider.context is not None
        assert oauth_provider.state_machine is not None

    @pytest.mark.anyio
    async def test_state_machine_starts_correctly(self, oauth_provider):
        """Test state machine begins in DISCOVERING_PROTECTED_RESOURCE."""
        assert oauth_provider.state_machine.current_state_type == OAuthStateType.DISCOVERING_PROTECTED_RESOURCE

    @pytest.mark.anyio
    async def test_auth_flow_with_valid_tokens(self, oauth_provider, mock_storage, valid_tokens):
        """Test flow skips to AUTHENTICATED when tokens are valid."""
        # Set up valid tokens in storage
        await mock_storage.set_tokens(valid_tokens)

        # Set token expiry time in the future
        oauth_provider.context.token_expiry_time = time.time() + 1800  # 30 minutes from now

        # Initialize should detect valid tokens and transition to AUTHENTICATED
        await oauth_provider.initialize()

        assert oauth_provider.state_machine.current_state_type == OAuthStateType.AUTHENTICATED

    @pytest.mark.anyio
    async def test_auth_flow_legacy_server_fallback(self, oauth_provider):
        """Test 404 on protected resource discovery transitions to OAuth metadata discovery."""
        # Get the discovering protected resource state
        state = oauth_provider.state_machine.current_state

        # Mock a 404 response
        mock_request = Mock()
        mock_response = Mock()
        mock_response.status_code = 404

        # Handle the 404 response
        next_state = await state.handle_response(mock_request, mock_response)

        # Should transition to discovering OAuth metadata (legacy server behavior)
        assert next_state == OAuthStateType.DISCOVERING_OAUTH_METADATA

    @pytest.mark.anyio
    async def test_invalid_state_transitions_raise_error(self, oauth_provider):
        """Test state machine prevents invalid transitions."""
        from mcp.client.auth import OAuthStateTransitionError

        # Try to transition to an invalid state
        with pytest.raises(OAuthStateTransitionError):
            await oauth_provider.state_machine.transition_to(OAuthStateType.EXCHANGING_TOKEN)

    def test_context_url_parsing(self, oauth_provider):
        """Test get_authorization_base_url() extracts base URLs correctly."""
        context = oauth_provider.context

        # Test with path
        assert context.get_authorization_base_url("https://api.example.com/v1/mcp") == "https://api.example.com"

        # Test with no path
        assert context.get_authorization_base_url("https://api.example.com") == "https://api.example.com"

        # Test with port
        assert (
            context.get_authorization_base_url("https://api.example.com:8080/path/to/mcp")
            == "https://api.example.com:8080"
        )

        # Test with query params
        assert (
            context.get_authorization_base_url("https://api.example.com/path?param=value") == "https://api.example.com"
        )

    @pytest.mark.anyio
    async def test_token_validity_checking(self, oauth_provider, mock_storage, valid_tokens):
        """Test is_token_valid() and can_refresh_token() logic."""
        context = oauth_provider.context

        # No tokens - should be invalid
        assert not context.is_token_valid()
        assert not context.can_refresh_token()

        # Set valid tokens and client info
        context.current_tokens = valid_tokens
        context.token_expiry_time = time.time() + 1800  # 30 minutes from now
        context.client_info = OAuthClientInformationFull(
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uris=[AnyUrl("http://localhost:3030/callback")],
        )

        # Should be valid
        assert context.is_token_valid()
        assert context.can_refresh_token()  # Has refresh token and client info

        # Expired tokens
        context.token_expiry_time = time.time() - 100  # Expired 100 seconds ago

        # Should be invalid but can refresh
        assert not context.is_token_valid()
        assert context.can_refresh_token()

        # No refresh token
        context.current_tokens.refresh_token = None

        # Should be invalid and cannot refresh
        assert not context.is_token_valid()
        assert not context.can_refresh_token()
