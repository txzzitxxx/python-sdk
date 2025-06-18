"""Token verification protocol and implementations."""

from typing import Any, Protocol, runtime_checkable

from mcp.server.auth.provider import AccessToken, OAuthAuthorizationServerProvider


@runtime_checkable
class TokenVerifier(Protocol):
    """Protocol for verifying bearer tokens."""

    async def verify_token(self, token: str) -> AccessToken | None:
        """Verify a bearer token and return access info if valid."""
        ...


class ProviderTokenVerifier:
    """Token verifier that uses an OAuthAuthorizationServerProvider."""

    def __init__(self, provider: OAuthAuthorizationServerProvider[Any, Any, Any]):
        self.provider = provider

    async def verify_token(self, token: str) -> AccessToken | None:
        """Verify token using the provider's load_access_token method."""
        return await self.provider.load_access_token(token)


class IntrospectionTokenVerifier:
    """Token verifier that uses OAuth 2.0 Token Introspection (RFC 7662)."""

    def __init__(self, introspection_endpoint: str):
        self.introspection_endpoint = introspection_endpoint

    async def verify_token(self, token: str) -> AccessToken | None:
        """Verify token via introspection endpoint."""
        import httpx

        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    self.introspection_endpoint,
                    data={"token": token},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )

                if response.status_code != 200:
                    return None

                data = response.json()
                if not data.get("active", False):
                    return None

                return AccessToken(
                    token=token,
                    client_id=data.get("client_id", "unknown"),
                    scopes=data.get("scope", "").split() if data.get("scope") else [],
                    expires_at=data.get("exp"),
                )
            except Exception:
                return None
