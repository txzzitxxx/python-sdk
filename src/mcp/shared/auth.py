from typing import Any, List, Literal, Optional

from pydantic import AnyHttpUrl, BaseModel, Field


class OAuthToken(BaseModel):
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
    # client_secret_post;
    # ie: we do not support client_secret_basic
    token_endpoint_auth_method: Literal["none", "client_secret_post"] = (
        "client_secret_post"
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


class OAuthClientInformationFull(OAuthClientMetadata):
    """
    RFC 7591 OAuth 2.0 Dynamic Client Registration full response
    (client information plus metadata).
    """

    client_id: str
    client_secret: Optional[str] = None
    client_id_issued_at: Optional[int] = None
    client_secret_expires_at: Optional[int] = None


class OAuthMetadata(BaseModel):
    """
    RFC 8414 OAuth 2.0 Authorization Server Metadata.
    See https://datatracker.ietf.org/doc/html/rfc8414#section-2
    """

    issuer: AnyHttpUrl
    authorization_endpoint: AnyHttpUrl
    token_endpoint: AnyHttpUrl
    registration_endpoint: AnyHttpUrl | None = None
    scopes_supported: list[str] | None = None
    response_types_supported: list[Literal["code"]] = ["code"]
    response_modes_supported: list[Literal["query", "fragment"]] | None = None
    grant_types_supported: (
        list[Literal["authorization_code", "refresh_token"]] | None
    ) = None
    token_endpoint_auth_methods_supported: (
        list[Literal["none", "client_secret_post"]] | None
    ) = None
    token_endpoint_auth_signing_alg_values_supported: None = None
    service_documentation: AnyHttpUrl | None = None
    ui_locales_supported: list[str] | None = None
    op_policy_uri: AnyHttpUrl | None = None
    op_tos_uri: AnyHttpUrl | None = None
    revocation_endpoint: AnyHttpUrl | None = None
    revocation_endpoint_auth_methods_supported: (
        list[Literal["client_secret_post"]] | None
    ) = None
    revocation_endpoint_auth_signing_alg_values_supported: None = None
    introspection_endpoint: AnyHttpUrl | None = None
    introspection_endpoint_auth_methods_supported: (
        list[Literal["client_secret_post"]] | None
    ) = None
    introspection_endpoint_auth_signing_alg_values_supported: None = None
    code_challenge_methods_supported: list[Literal["S256"]] | None = None
