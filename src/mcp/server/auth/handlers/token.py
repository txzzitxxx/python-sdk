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
    stringify_pydantic_error,
)
from mcp.server.auth.json_response import PydanticJSONResponse
from mcp.server.auth.middleware.client_auth import (
    ClientAuthenticator,
    ClientAuthRequest,
)
from mcp.server.auth.provider import OAuthServerProvider
from mcp.shared.auth import TokenErrorResponse, TokenSuccessResponse


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


def create_token_handler(
    provider: OAuthServerProvider, client_authenticator: ClientAuthenticator
) -> Callable:
    def response(obj: TokenSuccessResponse | TokenErrorResponse):
        status_code = 200
        if isinstance(obj, TokenErrorResponse):
            status_code = 400

        return PydanticJSONResponse(
            content=obj,
            status_code=status_code,
            headers={
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
            },
        )

    async def token_handler(request: Request):
        try:
            form_data = await request.form()
            token_request = TokenRequest.model_validate(dict(form_data)).root
        except ValidationError as validation_error:
            return response(
                TokenErrorResponse(
                    error="invalid_request",
                    error_description=stringify_pydantic_error(validation_error),
                )
            )
        client_info = await client_authenticator(token_request)

        if token_request.grant_type not in client_info.grant_types:
            return response(
                TokenErrorResponse(
                    error="unsupported_grant_type",
                    error_description=(
                        f"Unsupported grant type (supported grant types are "
                        f"{client_info.grant_types})"
                    ),
                )
            )

        tokens: TokenSuccessResponse

        match token_request:
            case AuthorizationCodeRequest():
                auth_code = await provider.load_authorization_code(
                    client_info, token_request.code
                )
                if auth_code is None or auth_code.client_id != token_request.client_id:
                    # if code belongs to different client, pretend it doesn't exist
                    return response(
                        TokenErrorResponse(
                            error="invalid_grant",
                            error_description="authorization code does not exist",
                        )
                    )

                # make auth codes expire after a deadline
                # see https://datatracker.ietf.org/doc/html/rfc6749#section-10.5
                if auth_code.expires_at < time.time():
                    return response(
                        TokenErrorResponse(
                            error="invalid_grant",
                            error_description="authorization code has expired",
                        )
                    )

                # verify redirect_uri doesn't change between /authorize and /tokens
                # see https://datatracker.ietf.org/doc/html/rfc6749#section-10.6
                if token_request.redirect_uri != auth_code.redirect_uri:
                    return response(
                        TokenErrorResponse(
                            error="invalid_request",
                            error_description=(
                        "redirect_uri didn't match the one used when creating auth code"
                    ),
                        )
                    )

                # Verify PKCE code verifier
                sha256 = hashlib.sha256(token_request.code_verifier.encode()).digest()
                hashed_code_verifier = (
                    base64.urlsafe_b64encode(sha256).decode().rstrip("=")
                )

                if hashed_code_verifier != auth_code.code_challenge:
                    # see https://datatracker.ietf.org/doc/html/rfc7636#section-4.6
                    return response(
                        TokenErrorResponse(
                            error="invalid_grant",
                            error_description="incorrect code_verifier",
                        )
                    )

                # Exchange authorization code for tokens
                tokens = await provider.exchange_authorization_code(
                    client_info, auth_code
                )

            case RefreshTokenRequest():
                refresh_token = await provider.load_refresh_token(
                    client_info, token_request.refresh_token
                )
                if (
                    refresh_token is None
                    or refresh_token.client_id != token_request.client_id
                ):
                    # if token belongs to different client, pretend it doesn't exist
                    return response(
                        TokenErrorResponse(
                            error="invalid_grant",
                            error_description="refresh token does not exist",
                        )
                    )

                if refresh_token.expires_at and refresh_token.expires_at < time.time():
                    # if the refresh token has expired, pretend it doesn't exist
                    return response(
                        TokenErrorResponse(
                            error="invalid_grant",
                            error_description="refresh token has expired",
                        )
                    )

                # Parse scopes if provided
                scopes = (
                    token_request.scope.split(" ")
                    if token_request.scope
                    else refresh_token.scopes
                )

                for scope in scopes:
                    if scope not in refresh_token.scopes:
                        return response(
                            TokenErrorResponse(
                                error="invalid_scope",
                                error_description=(
                        f"cannot request scope `{scope}` not provided by refresh token"
                    ),
                            )
                        )

                # Exchange refresh token for new tokens
                tokens = await provider.exchange_refresh_token(
                    client_info, refresh_token, scopes
                )

        return response(tokens)

    return token_handler
