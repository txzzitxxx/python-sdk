"""
Handler for OAuth 2.0 Token Revocation.

Corresponds to TypeScript file: src/server/auth/handlers/revoke.ts
"""

from typing import Callable

from pydantic import ValidationError
from starlette.requests import Request
from starlette.responses import Response

from mcp.server.auth.errors import (
    stringify_pydantic_error,
)
from mcp.server.auth.json_response import PydanticJSONResponse
from mcp.server.auth.middleware.client_auth import (
    ClientAuthenticator,
    ClientAuthRequest,
)
from mcp.server.auth.provider import OAuthServerProvider, OAuthTokenRevocationRequest
from mcp.shared.auth import TokenErrorResponse


class RevocationRequest(OAuthTokenRevocationRequest, ClientAuthRequest):
    pass


def create_revocation_handler(
    provider: OAuthServerProvider, client_authenticator: ClientAuthenticator
) -> Callable:
    async def revocation_handler(request: Request) -> Response:
        """
        Handler for the OAuth 2.0 Token Revocation endpoint.
        """
        try:
            form_data = await request.form()
            revocation_request = RevocationRequest.model_validate(dict(form_data))
        except ValidationError as e:
            return PydanticJSONResponse(
                status_code=400,
                content=TokenErrorResponse(
                    error="invalid_request",
                    error_description=stringify_pydantic_error(e),
                ),
            )

        # Authenticate client
        client_auth_result = await client_authenticator(revocation_request)

        # Revoke token
        if provider.revoke_token:
            await provider.revoke_token(client_auth_result, revocation_request)

        # Return successful empty response
        return Response(
            status_code=200,
            headers={
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
            },
        )

    return revocation_handler
