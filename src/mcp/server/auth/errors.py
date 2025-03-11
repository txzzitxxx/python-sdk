"""
OAuth error classes for MCP authorization.

Corresponds to TypeScript file: src/server/auth/errors.ts
"""

from typing import Dict

from pydantic import ValidationError


class OAuthError(Exception):
    """
    Base class for all OAuth errors.

    Corresponds to OAuthError in src/server/auth/errors.ts
    """

    error_code: str = "server_error"

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message

    def to_response_object(self) -> Dict[str, str]:
        """Convert error to JSON response object."""
        return {"error": self.error_code, "error_description": self.message}


class ServerError(OAuthError):
    """
    Server error.

    Corresponds to ServerError in src/server/auth/errors.ts
    """

    error_code = "server_error"


class InvalidRequestError(OAuthError):
    """
    Invalid request error.

    Corresponds to InvalidRequestError in src/server/auth/errors.ts
    """

    error_code = "invalid_request"


class InvalidClientError(OAuthError):
    """
    Invalid client error.

    Corresponds to InvalidClientError in src/server/auth/errors.ts
    """

    error_code = "invalid_client"


class InvalidGrantError(OAuthError):
    """
    Invalid grant error.

    Corresponds to InvalidGrantError in src/server/auth/errors.ts
    """

    error_code = "invalid_grant"


class UnauthorizedClientError(OAuthError):
    """
    Unauthorized client error.

    Corresponds to UnauthorizedClientError in src/server/auth/errors.ts
    """

    error_code = "unauthorized_client"


class UnsupportedGrantTypeError(OAuthError):
    """
    Unsupported grant type error.

    Corresponds to UnsupportedGrantTypeError in src/server/auth/errors.ts
    """

    error_code = "unsupported_grant_type"


class UnsupportedResponseTypeError(OAuthError):
    """
    Unsupported response type error.

    Corresponds to UnsupportedResponseTypeError in src/server/auth/errors.ts
    """

    error_code = "unsupported_response_type"


class InvalidScopeError(OAuthError):
    """
    Invalid scope error.

    Corresponds to InvalidScopeError in src/server/auth/errors.ts
    """

    error_code = "invalid_scope"


class AccessDeniedError(OAuthError):
    """
    Access denied error.

    Corresponds to AccessDeniedError in src/server/auth/errors.ts
    """

    error_code = "access_denied"


class TemporarilyUnavailableError(OAuthError):
    """
    Temporarily unavailable error.

    Corresponds to TemporarilyUnavailableError in src/server/auth/errors.ts
    """

    error_code = "temporarily_unavailable"


class InvalidTokenError(OAuthError):
    """
    Invalid token error.

    Corresponds to InvalidTokenError in src/server/auth/errors.ts
    """

    error_code = "invalid_token"


class InsufficientScopeError(OAuthError):
    """
    Insufficient scope error.

    Corresponds to InsufficientScopeError in src/server/auth/errors.ts
    """

    error_code = "insufficient_scope"


def stringify_pydantic_error(validation_error: ValidationError) -> str:
    return "\n".join(
        f"{'.'.join(str(loc) for loc in e['loc'])}: {e['msg']}"
        for e in validation_error.errors()
    )
