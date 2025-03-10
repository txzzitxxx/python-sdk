"""
Handler for OAuth 2.0 Token endpoint.

Corresponds to TypeScript file: src/server/auth/handlers/token.ts
"""

import base64
import hashlib
from typing import Annotated, Callable, Literal, Optional, Union

from pydantic import Field, RootModel, ValidationError
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
    grant_type: Literal["authorization_code"]
    code: str = Field(..., description="The authorization code")
    code_verifier: str = Field(..., description="PKCE code verifier")
    # TODO: this should take redirect_uri


class RefreshTokenRequest(ClientAuthRequest):
    grant_type: Literal["refresh_token"]
    refresh_token: str = Field(..., description="The refresh token")
    scope: Optional[str] = Field(None, description="Optional scope parameter")


class TokenRequest(RootModel):
    root: Annotated[
        Union[AuthorizationCodeRequest, RefreshTokenRequest],
        Field(discriminator="grant_type"),
    ]



def create_token_handler(
    provider: OAuthServerProvider, client_authenticator: ClientAuthenticator
) -> Callable:
    async def token_handler(request: Request):
        try:
            token_request = TokenRequest.model_validate_json(await request.body()).root
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
                # TODO: verify that the redirect URIs match
                # see https://datatracker.ietf.org/doc/html/rfc6749#section-10.6
                # TODO: enforce TTL on the authorization code

                # Verify PKCE code verifier
                expected_challenge = await provider.challenge_for_authorization_code(
                    client_info, token_request.code
                )
                if expected_challenge is None:
                    raise InvalidRequestError("Invalid authorization code")

                # Calculate challenge from verifier
                sha256 = hashlib.sha256(token_request.code_verifier.encode()).digest()
                actual_challenge = base64.urlsafe_b64encode(sha256).decode().rstrip("=")

                if actual_challenge != expected_challenge:
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
