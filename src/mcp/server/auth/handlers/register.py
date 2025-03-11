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
from starlette.responses import JSONResponse, Response

from mcp.server.auth.errors import (
    InvalidRequestError,
    OAuthError,
    ServerError,
    stringify_pydantic_error,
)
from mcp.server.auth.json_response import PydanticJSONResponse
from mcp.server.auth.provider import OAuthRegisteredClientsStore
from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata

class ErrorResponse(BaseModel):
    error: Literal["invalid_redirect_uri", "invalid_client_metadata", "invalid_software_statement", "unapproved_software_statement"]
    error_description: str


def create_registration_handler(
    clients_store: OAuthRegisteredClientsStore, client_secret_expiry_seconds: int | None
) -> Callable:
    """
    Create a handler for OAuth 2.0 Dynamic Client Registration.

    Corresponds to clientRegistrationHandler in src/server/auth/handlers/register.ts

    Args:
        clients_store: The store for registered clients
        client_secret_expiry_seconds: Optional expiry time for client secrets

    Returns:
        A Starlette endpoint handler function
    """

    async def registration_handler(request: Request) -> Response:
        """
        Handler for the OAuth 2.0 Dynamic Client Registration endpoint.

        Args:
            request: The Starlette request

        Returns:
            JSON response with client information or error
        """
        try:
            # Parse request body as JSON
            try:
                body = await request.json()
                client_metadata = OAuthClientMetadata.model_validate(body)
            except ValidationError as validation_error:
                return PydanticJSONResponse(content=ErrorResponse(
                    error="invalid_client_metadata",
                    error_description=stringify_pydantic_error(validation_error)
                ), status_code=400)

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
                **client_metadata.model_dump(exclude_unset=True),
                policy_uri=client_metadata.policy_uri,
                jwks_uri=client_metadata.jwks_uri,
                jwks=client_metadata.jwks,
                software_id=client_metadata.software_id,
                software_version=client_metadata.software_version,
            )
            # Register client
            client = await clients_store.register_client(client_info)
            if not client:
                raise ServerError("Failed to register client")

            # Return client information
            return PydanticJSONResponse(content=client, status_code=201)

        except OAuthError as e:
            # Handle OAuth errors
            status_code = 500 if isinstance(e, ServerError) else 400
            return JSONResponse(status_code=status_code, content=e.to_response_object())

    return registration_handler