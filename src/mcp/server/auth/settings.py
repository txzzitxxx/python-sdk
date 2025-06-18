from pydantic import AnyHttpUrl, BaseModel, Field


class ClientRegistrationOptions(BaseModel):
    enabled: bool = False
    client_secret_expiry_seconds: int | None = None
    valid_scopes: list[str] | None = None
    default_scopes: list[str] | None = None


class RevocationOptions(BaseModel):
    enabled: bool = False


class AuthSettings(BaseModel):
    issuer_url: AnyHttpUrl = Field(
        ...,
        description="URL advertised as OAuth issuer; this should be the URL the server " "is reachable at",
    )
    service_documentation_url: AnyHttpUrl | None = None
    client_registration_options: ClientRegistrationOptions | None = None
    revocation_options: RevocationOptions | None = None
    required_scopes: list[str] | None = None
    resource_url: AnyHttpUrl | None = Field(
        None,
        description="URL of the protected resource for RFC 9728 metadata discovery",
    )
    resource_name: str | None = Field(
        None,
        description="Name of the protected resource",
    )
