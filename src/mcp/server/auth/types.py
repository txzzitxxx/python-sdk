"""
Authorization types for MCP server.

Corresponds to TypeScript file: src/server/auth/types.ts
"""

from typing import List, Optional

from pydantic import BaseModel


class AuthInfo(BaseModel):
    """
    Information about a validated access token, provided to request handlers.

    Corresponds to AuthInfo in src/server/auth/types.ts
    """

    token: str
    client_id: str
    scopes: List[str]
    expires_at: Optional[int] = None
