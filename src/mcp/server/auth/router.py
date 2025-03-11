from dataclasses import dataclass

from pydantic import AnyUrl
from starlette.routing import Route, Router

from mcp.server.auth.handlers.authorize import AuthorizationHandler
from mcp.server.auth.handlers.metadata import MetadataHandler
from mcp.server.auth.handlers.register import RegistrationHandler
from mcp.server.auth.handlers.revoke import RevocationHandler
from mcp.server.auth.handlers.token import TokenHandler
from mcp.server.auth.middleware.client_auth import ClientAuthenticator
from mcp.server.auth.provider import OAuthServerProvider
from mcp.shared.auth import OAuthMetadata


@dataclass
class ClientRegistrationOptions:
    enabled: bool = False
    client_secret_expiry_seconds: int | None = None


@dataclass
class RevocationOptions:
    enabled: bool = False


def validate_issuer_url(url: AnyUrl):
    """
    Validate that the issuer URL meets OAuth 2.0 requirements.

    Args:
        url: The issuer URL to validate

    Raises:
        ValueError: If the issuer URL is invalid
    """

    # RFC 8414 requires HTTPS, but we allow localhost HTTP for testing
    if (
        url.scheme != "https"
        and url.host != "localhost"
        and not (url.host is not None and url.host.startswith("127.0.0.1"))
    ):
        raise ValueError("Issuer URL must be HTTPS")

    # No fragments or query parameters allowed
    if url.fragment:
        raise ValueError("Issuer URL must not have a fragment")
    if url.query:
        raise ValueError("Issuer URL must not have a query string")


AUTHORIZATION_PATH = "/authorize"
TOKEN_PATH = "/token"
REGISTRATION_PATH = "/register"
REVOCATION_PATH = "/revoke"


def create_auth_router(
    provider: OAuthServerProvider,
    issuer_url: AnyUrl,
    service_documentation_url: AnyUrl | None = None,
    client_registration_options: ClientRegistrationOptions | None = None,
    revocation_options: RevocationOptions | None = None,
) -> Router:
    """
    Create a Starlette router with standard MCP authorization endpoints.

    Args:
        provider: OAuth server provider
        issuer_url: Issuer URL for the authorization server
        service_documentation_url: Optional URL for service documentation
        client_registration_options: Options for client registration
        revocation_options: Options for token revocation

    Returns:
        Starlette router with authorization endpoints
    """

    validate_issuer_url(issuer_url)

    client_registration_options = (
        client_registration_options or ClientRegistrationOptions()
    )
    revocation_options = revocation_options or RevocationOptions()
    metadata = build_metadata(
        issuer_url,
        service_documentation_url,
        client_registration_options,
        revocation_options,
    )
    client_authenticator = ClientAuthenticator(provider.clients_store)

    # Create routes
    auth_router = Router(
        routes=[
            Route(
                "/.well-known/oauth-authorization-server",
                endpoint=MetadataHandler(metadata).handle,
                methods=["GET"],
            ),
            Route(
                AUTHORIZATION_PATH,
                endpoint=AuthorizationHandler(provider).handle,
                methods=["GET", "POST"],
            ),
            Route(
                TOKEN_PATH,
                endpoint=TokenHandler(provider, client_authenticator).handle,
                methods=["POST"],
            ),
        ]
    )

    if client_registration_options.enabled:
        registration_handler = RegistrationHandler(
            provider.clients_store,
            client_secret_expiry_seconds=client_registration_options.client_secret_expiry_seconds,
        )
        auth_router.routes.append(
            Route(
                REGISTRATION_PATH,
                endpoint=registration_handler.handle,
                methods=["POST"],
            )
        )

    if revocation_options.enabled:
        revocation_handler = RevocationHandler(provider, client_authenticator)
        auth_router.routes.append(
            Route(REVOCATION_PATH, endpoint=revocation_handler.handle, methods=["POST"])
        )

    return auth_router


def build_metadata(
    issuer_url: AnyUrl,
    service_documentation_url: AnyUrl | None,
    client_registration_options: ClientRegistrationOptions,
    revocation_options: RevocationOptions,
) -> OAuthMetadata:
    issuer_url_str = str(issuer_url).rstrip("/")
    # Create metadata
    metadata = OAuthMetadata(
        issuer=issuer_url_str,
        service_documentation=str(service_documentation_url).rstrip("/")
        if service_documentation_url
        else None,
        authorization_endpoint=f"{issuer_url_str}{AUTHORIZATION_PATH}",
        response_types_supported=["code"],
        code_challenge_methods_supported=["S256"],
        token_endpoint=f"{issuer_url_str}{TOKEN_PATH}",
        token_endpoint_auth_methods_supported=["client_secret_post"],
        grant_types_supported=["authorization_code", "refresh_token"],
    )

    # Add registration endpoint if supported
    if client_registration_options.enabled:
        metadata.registration_endpoint = f"{issuer_url_str}{REGISTRATION_PATH}"

    # Add revocation endpoint if supported
    if revocation_options.enabled:
        metadata.revocation_endpoint = f"{issuer_url_str}{REVOCATION_PATH}"
        metadata.revocation_endpoint_auth_methods_supported = ["client_secret_post"]

    return metadata
