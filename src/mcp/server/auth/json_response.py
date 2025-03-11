from typing import Any

from starlette.responses import JSONResponse


class PydanticJSONResponse(JSONResponse):
    def render(self, content: Any) -> bytes:
        return content.model_dump_json(exclude_none=True).encode("utf-8")
