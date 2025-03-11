"""
OAuth error classes for MCP authorization.

Corresponds to TypeScript file: src/server/auth/errors.ts
"""

from typing import Literal

from pydantic import BaseModel, ValidationError

ErrorCode = Literal["invalid_request", "invalid_client"]

class ErrorResponse(BaseModel):
    error: ErrorCode
    error_description: str


class OAuthError(Exception):
    """
    Base class for all OAuth errors.

    Corresponds to OAuthError in src/server/auth/errors.ts
    """

    error_code: ErrorCode

    def __init__(self, error_description: str):
        super().__init__(error_description)
        self.error_description = error_description

    def error_response(self) -> ErrorResponse:
        return ErrorResponse(
            error=self.error_code,
            error_description=self.error_description,
        )


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


def stringify_pydantic_error(validation_error: ValidationError) -> str:
    return "\n".join(
        f"{'.'.join(str(loc) for loc in e['loc'])}: {e['msg']}"
        for e in validation_error.errors()
    )
