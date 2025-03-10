"""
Handler for OAuth 2.0 Token endpoint.

Corresponds to TypeScript file: src/server/auth/handlers/token.ts
"""

import base64
import hashlib
import time
from typing import Annotated, Callable, Literal, Optional, Union

from pydantic import AnyHttpUrl, Field, RootModel, ValidationError
from starlette.requests import Request

from mcp.server.auth.errors import (
    InvalidRequestError,
)
from mcp.server.auth.json_response import PydanticJSONResponse
from mcp.server.auth.middleware.client_auth import (
    ClientAuthenticator,
    ClientAuthRequest,
)
from mcp.server.auth.provider import OAuthServerProvider
from mcp.shared.auth import OAuthTokens


class AuthorizationCodeRequest(ClientAuthRequest):
    # See https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
    grant_type: Literal["authorization_code"]
    code: str = Field(..., description="The authorization code")
    redirect_uri: AnyHttpUrl | None = Field(
        ..., description="Must be the same as redirect URI provided in /authorize"
    )
    client_id: str
    # See https://datatracker.ietf.org/doc/html/rfc7636#section-4.5
    code_verifier: str = Field(..., description="PKCE code verifier")


class RefreshTokenRequest(ClientAuthRequest):
    # See https://datatracker.ietf.org/doc/html/rfc6749#section-6
    grant_type: Literal["refresh_token"]
    refresh_token: str = Field(..., description="The refresh token")
    scope: Optional[str] = Field(None, description="Optional scope parameter")


class TokenRequest(RootModel):
    root: Annotated[
        Union[AuthorizationCodeRequest, RefreshTokenRequest],
        Field(discriminator="grant_type"),
    ]

AUTH_CODE_TTL = 300 # seconds

def create_token_handler(
    provider: OAuthServerProvider, client_authenticator: ClientAuthenticator
) -> Callable:
    async def token_handler(request: Request):
        try:
            form_data = await request.form()
            token_request = TokenRequest.model_validate(dict(form_data)).root
        except ValidationError as e:
            raise InvalidRequestError(f"Invalid request body: {e}")
        client_info = await client_authenticator(token_request)

        if token_request.grant_type not in client_info.grant_types:
            raise InvalidRequestError(
                f"Unsupported grant type (supported grant types are "
                f"{client_info.grant_types})"
            )

        tokens: OAuthTokens

        match token_request:
            case AuthorizationCodeRequest():
                auth_code_metadata = await provider.load_authorization_code_metadata(
                    client_info, token_request.code
                )
                if auth_code_metadata is None or auth_code_metadata.client_id != token_request.client_id:
                    raise InvalidRequestError("Invalid authorization code")

                # make auth codes expire after a deadline
                # see https://datatracker.ietf.org/doc/html/rfc6749#section-10.5
                expires_at = auth_code_metadata.issued_at + AUTH_CODE_TTL
                if expires_at < time.time():
                    raise InvalidRequestError("authorization code has expired")

                # verify redirect_uri doesn't change between /authorize and /tokens
                # see https://datatracker.ietf.org/doc/html/rfc6749#section-10.6
                if token_request.redirect_uri != auth_code_metadata.redirect_uri:
                    raise InvalidRequestError("redirect_uri did not match redirect_uri used when authorization code was created")

                # Verify PKCE code verifier
                sha256 = hashlib.sha256(token_request.code_verifier.encode()).digest()
                hashed_code_verifier = base64.urlsafe_b64encode(sha256).decode().rstrip("=")

                if hashed_code_verifier != auth_code_metadata.code_challenge:
                    raise InvalidRequestError(
                        "code_verifier does not match the challenge"
                    )

                # Exchange authorization code for tokens
                tokens = await provider.exchange_authorization_code(
                    client_info, token_request.code
                )

            case RefreshTokenRequest():
                # Parse scopes if provided
                scopes = token_request.scope.split(" ") if token_request.scope else None

                # Exchange refresh token for new tokens
                tokens = await provider.exchange_refresh_token(
                    client_info, token_request.refresh_token, scopes
                )

        return PydanticJSONResponse(
            content=tokens,
            headers={
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
            },
        )

    return token_handler
