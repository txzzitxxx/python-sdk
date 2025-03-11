import time

from pydantic import BaseModel

from mcp.server.auth.errors import InvalidClientError
from mcp.server.auth.provider import OAuthRegisteredClientsStore
from mcp.shared.auth import OAuthClientInformationFull


class ClientAuthRequest(BaseModel):
    # TODO: mix this directly into TokenRequest

    client_id: str
    client_secret: str | None = None


class ClientAuthenticator:
    """
    ClientAuthenticator is a callable which validates requests from a client
    application,
    used to verify /token and /revoke calls.
    If, during registration, the client requested to be issued a secret, the
    authenticator asserts that /token and /register calls must be authenticated with
    that same token.
    NOTE: clients can opt for no authentication during registration, in which case this
    logic is skipped.
    """

    def __init__(self, clients_store: OAuthRegisteredClientsStore):
        """
        Initialize the dependency.

        Args:
            clients_store: Store to look up client information
        """
        self.clients_store = clients_store

    async def __call__(self, request: ClientAuthRequest) -> OAuthClientInformationFull:
        # Look up client information
        client = await self.clients_store.get_client(request.client_id)
        if not client:
            raise InvalidClientError("Invalid client_id")

        # If client from the store expects a secret, validate that the request provides
        # that secret
        if client.client_secret:
            if not request.client_secret:
                raise InvalidClientError("Client secret is required")

            if client.client_secret != request.client_secret:
                raise InvalidClientError("Invalid client_secret")

            if (
                client.client_secret_expires_at
                and client.client_secret_expires_at < int(time.time())
            ):
                raise InvalidClientError("Client secret has expired")

        return client
