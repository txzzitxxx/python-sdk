"""
Handler for OAuth 2.0 Authorization Server Metadata.

Corresponds to TypeScript file: src/server/auth/handlers/metadata.ts
"""

from typing import Any, Callable

from starlette.requests import Request
from starlette.responses import JSONResponse, Response


def create_metadata_handler(metadata: dict[str, Any]) -> Callable:
    """
    Create a handler for OAuth 2.0 Authorization Server Metadata.

    Corresponds to metadataHandler in src/server/auth/handlers/metadata.ts

    Args:
        metadata: The metadata to return in the response

    Returns:
        A Starlette endpoint handler function
    """

    async def metadata_handler(request: Request) -> Response:
        """
        Handler for the OAuth 2.0 Authorization Server Metadata endpoint.

        Args:
            request: The Starlette request

        Returns:
            JSON response with the authorization server metadata
        """
        # Remove any None values from metadata
        clean_metadata = {k: v for k, v in metadata.items() if v is not None}

        return JSONResponse(
            content=clean_metadata,
            headers={"Cache-Control": "public, max-age=3600"},  # Cache for 1 hour
        )

    return metadata_handler
