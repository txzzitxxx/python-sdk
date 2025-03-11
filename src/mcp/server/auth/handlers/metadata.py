from dataclasses import dataclass
from typing import Any

from starlette.requests import Request
from starlette.responses import JSONResponse, Response


@dataclass
class MetadataHandler:
    metadata: dict[str, Any]

    async def handle(self, request: Request) -> Response:
        # Remove any None values from metadata
        clean_metadata = {k: v for k, v in self.metadata.items() if v is not None}

        return JSONResponse(
            content=clean_metadata,
            headers={"Cache-Control": "public, max-age=3600"},  # Cache for 1 hour
        )
