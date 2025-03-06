"""
Authorization types and models for MCP OAuth implementation.

Corresponds to TypeScript file: src/shared/auth.ts
"""

from typing import Any, Dict, List, Optional, Union
from pydantic import AnyHttpUrl, BaseModel, Field, field_validator, model_validator


class OAuthErrorResponse(BaseModel):
    """
    OAuth 2.1 error response.

    Corresponds to OAuthErrorResponseSchema in src/shared/auth.ts
    """
    error: str
    error_description: Optional[str] = None
    error_uri: Optional[AnyHttpUrl] = None


class OAuthTokens(BaseModel):
    """
    OAuth 2.1 token response.

    Corresponds to OAuthTokensSchema in src/shared/auth.ts
    """
    access_token: str
    token_type: str
    expires_in: Optional[int] = None
    scope: Optional[str] = None
    refresh_token: Optional[str] = None


class OAuthClientMetadata(BaseModel):
    """
    RFC 7591 OAuth 2.0 Dynamic Client Registration metadata.

    Corresponds to OAuthClientMetadataSchema in src/shared/auth.ts
    """
    redirect_uris: List[AnyHttpUrl] = Field(..., min_length=1)
    token_endpoint_auth_method: Optional[str]
    grant_types: Optional[List[str]]
    response_types: Optional[List[str]] = None
    client_name: Optional[str] = None
    client_uri: Optional[AnyHttpUrl] = None
    logo_uri: Optional[AnyHttpUrl] = None
    scope: Optional[str] = None
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


class OAuthTokenRevocationRequest(BaseModel):
    """
    RFC 7009 OAuth 2.0 Token Revocation request.

    Corresponds to OAuthTokenRevocationRequestSchema in src/shared/auth.ts
    """
    token: str
    token_type_hint: Optional[str] = None


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