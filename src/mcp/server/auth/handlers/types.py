from typing import Protocol

from starlette.requests import Request
from starlette.responses import Response


class HandlerFn(Protocol):
    async def __call__(self, request: Request) -> Response: ...
