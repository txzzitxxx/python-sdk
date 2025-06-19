"""Token verification protocol."""

from typing import Protocol, runtime_checkable

from mcp.server.auth.provider import AccessToken


@runtime_checkable
class TokenVerifier(Protocol):
    """Protocol for verifying bearer tokens."""

    async def verify_token(self, token: str) -> AccessToken | None:
        """Verify a bearer token and return access info if valid."""
        ...
