from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, ValidationError
from starlette.requests import Request
from starlette.responses import Response

from mcp.server.auth.errors import (
    stringify_pydantic_error,
)
from mcp.server.auth.json_response import PydanticJSONResponse
from mcp.server.auth.middleware.client_auth import (
    ClientAuthenticator,
)
from mcp.server.auth.provider import OAuthServerProvider


class RevocationRequest(BaseModel):
    """
    # See https://datatracker.ietf.org/doc/html/rfc7009#section-2.1
    """

    token: str
    token_type_hint: Literal["access_token", "refresh_token"] | None = None


class RevocationErrorResponse(BaseModel):
    error: Literal["invalid_request",]
    error_description: str | None = None


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
                content=RevocationErrorResponse(
                    error="invalid_request",
                    error_description=stringify_pydantic_error(e),
                ),
            )

        # Revoke token
        await self.provider.revoke_token(
            revocation_request.token, revocation_request.token_type_hint
        )

        # Return successful empty response
        return Response(
            status_code=200,
            headers={
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
            },
        )
