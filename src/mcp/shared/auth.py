"""
Authorization types and models for MCP OAuth implementation.

Corresponds to TypeScript file: src/shared/auth.ts
"""

from typing import Any, List, Literal, Optional

from pydantic import AnyHttpUrl, BaseModel, Field


class TokenErrorResponse(BaseModel):
    """
    See https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
    """

    error: Literal[
        "invalid_request",
        "invalid_client",
        "invalid_grant",
        "unauthorized_client",
        "unsupported_grant_type",
        "invalid_scope",
    ]
    error_description: Optional[str] = None
    error_uri: Optional[AnyHttpUrl] = None


class TokenSuccessResponse(BaseModel):
    """
    See https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
    """

    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: Optional[int] = None
    scope: Optional[str] = None
    refresh_token: Optional[str] = None


class OAuthClientMetadata(BaseModel):
    """
    RFC 7591 OAuth 2.0 Dynamic Client Registration metadata.
    See https://datatracker.ietf.org/doc/html/rfc7591#section-2
    for the full specification.
    """

    redirect_uris: List[AnyHttpUrl] = Field(..., min_length=1)
    # token_endpoint_auth_method: this implementation only supports none &
    # client_secret_basic;
    # ie: we do not support client_secret_post
    token_endpoint_auth_method: Literal["none", "client_secret_basic"] = (
        "client_secret_basic"
    )
    # grant_types: this implementation only supports authorization_code & refresh_token
    grant_types: List[Literal["authorization_code", "refresh_token"]] = [
        "authorization_code"
    ]
    # this implementation only supports code; ie: it does not support implicit grants
    response_types: List[Literal["code"]] = ["code"]
    scope: Optional[str] = None

    # these fields are currently unused, but we support & store them for potential
    # future use
    client_name: Optional[str] = None
    client_uri: Optional[AnyHttpUrl] = None
    logo_uri: Optional[AnyHttpUrl] = None
    contacts: Optional[List[str]] = None
    tos_uri: Optional[AnyHttpUrl] = None
    policy_uri: Optional[AnyHttpUrl] = None
    jwks_uri: Optional[AnyHttpUrl] = None
    jwks: Optional[Any] = None
    software_id: Optional[str] = None
    software_version: Optional[str] = None


class OAuthClientInformation(BaseModel):
    """
    RFC 7591 OAuth 2.0 Dynamic Client Registration client information.

    Corresponds to OAuthClientInformationSchema in src/shared/auth.ts
    """

    client_id: str
    client_secret: Optional[str] = None
    client_id_issued_at: Optional[int] = None
    client_secret_expires_at: Optional[int] = None


class OAuthClientInformationFull(OAuthClientMetadata, OAuthClientInformation):
    """
    RFC 7591 OAuth 2.0 Dynamic Client Registration full response
    (client information plus metadata).

    Corresponds to OAuthClientInformationFullSchema in src/shared/auth.ts
    """

    pass


class OAuthClientRegistrationError(BaseModel):
    """
    RFC 7591 OAuth 2.0 Dynamic Client Registration error response.

    Corresponds to OAuthClientRegistrationErrorSchema in src/shared/auth.ts
    """

    error: str
    error_description: Optional[str] = None


class OAuthMetadata(BaseModel):
    """
    RFC 8414 OAuth 2.0 Authorization Server Metadata.

    Corresponds to OAuthMetadataSchema in src/shared/auth.ts
    """

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    registration_endpoint: Optional[str] = None
    scopes_supported: Optional[List[str]] = None
    response_types_supported: List[str]
    response_modes_supported: Optional[List[str]] = None
    grant_types_supported: Optional[List[str]] = None
    token_endpoint_auth_methods_supported: Optional[List[str]] = None
    token_endpoint_auth_signing_alg_values_supported: Optional[List[str]] = None
    service_documentation: Optional[str] = None
    revocation_endpoint: Optional[str] = None
    revocation_endpoint_auth_methods_supported: Optional[List[str]] = None
    revocation_endpoint_auth_signing_alg_values_supported: Optional[List[str]] = None
    introspection_endpoint: Optional[str] = None
    introspection_endpoint_auth_methods_supported: Optional[List[str]] = None
    introspection_endpoint_auth_signing_alg_values_supported: Optional[List[str]] = None
    code_challenge_methods_supported: Optional[List[str]] = None
