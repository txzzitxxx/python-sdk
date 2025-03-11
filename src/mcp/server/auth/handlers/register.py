"""
Handler for OAuth 2.0 Dynamic Client Registration.

Corresponds to TypeScript file: src/server/auth/handlers/register.ts
"""

import secrets
import time
from typing import Callable, Literal
from uuid import uuid4

from pydantic import BaseModel, ValidationError
from starlette.requests import Request
from starlette.responses import Response

from mcp.server.auth.errors import stringify_pydantic_error
from mcp.server.auth.json_response import PydanticJSONResponse
from mcp.server.auth.provider import OAuthRegisteredClientsStore
from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata


class ErrorResponse(BaseModel):
    error: Literal[
        "invalid_redirect_uri",
        "invalid_client_metadata",
        "invalid_software_statement",
        "unapproved_software_statement",
    ]
    error_description: str


def create_registration_handler(
    clients_store: OAuthRegisteredClientsStore, client_secret_expiry_seconds: int | None
) -> Callable:
    async def registration_handler(request: Request) -> Response:
        # Implements dynamic client registration as defined in https://datatracker.ietf.org/doc/html/rfc7591#section-3.1
        try:
            # Parse request body as JSON
            body = await request.json()
            client_metadata = OAuthClientMetadata.model_validate(body)
        except ValidationError as validation_error:
            return PydanticJSONResponse(
                content=ErrorResponse(
                    error="invalid_client_metadata",
                    error_description=stringify_pydantic_error(validation_error),
                ),
                status_code=400,
            )

        client_id = str(uuid4())
        client_secret = None
        if client_metadata.token_endpoint_auth_method != "none":
            # cryptographically secure random 32-byte hex string
            client_secret = secrets.token_hex(32)

        client_id_issued_at = int(time.time())
        client_secret_expires_at = (
            client_id_issued_at + client_secret_expiry_seconds
            if client_secret_expiry_seconds is not None
            else None
        )

        client_info = OAuthClientInformationFull(
            client_id=client_id,
            client_id_issued_at=client_id_issued_at,
            client_secret=client_secret,
            client_secret_expires_at=client_secret_expires_at,
            # passthrough information from the client request
            redirect_uris=client_metadata.redirect_uris,
            token_endpoint_auth_method=client_metadata.token_endpoint_auth_method,
            grant_types=client_metadata.grant_types,
            response_types=client_metadata.response_types,
            client_name=client_metadata.client_name,
            client_uri=client_metadata.client_uri,
            logo_uri=client_metadata.logo_uri,
            scope=client_metadata.scope,
            contacts=client_metadata.contacts,
            tos_uri=client_metadata.tos_uri,
            policy_uri=client_metadata.policy_uri,
            jwks_uri=client_metadata.jwks_uri,
            jwks=client_metadata.jwks,
            software_id=client_metadata.software_id,
            software_version=client_metadata.software_version,
        )
        # Register client
        client = await clients_store.register_client(client_info)

        # Return client information
        return PydanticJSONResponse(content=client, status_code=201)

    return registration_handler
