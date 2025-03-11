"""
Handler for OAuth 2.0 Token Revocation.

Corresponds to TypeScript file: src/server/auth/handlers/revoke.ts
"""

from dataclasses import dataclass

from pydantic import ValidationError
from starlette.requests import Request
from starlette.responses import Response

from mcp.server.auth.errors import (
    InvalidClientError,
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


@dataclass
class RevocationHandler:
    provider: OAuthServerProvider
    client_authenticator: ClientAuthenticator

    async def handle(self, request: Request) -> Response:
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
        try:
            client_auth_result = await self.client_authenticator(revocation_request)
        except InvalidClientError as e:
            return PydanticJSONResponse(status_code=401, content=e.error_response())

        # Revoke token
        if self.provider.revoke_token:
            await self.provider.revoke_token(client_auth_result, revocation_request)

        # Return successful empty response
        return Response(
            status_code=200,
            headers={
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
            },
        )
