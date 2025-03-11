from pydantic import BaseModel


class AuthInfo(BaseModel):
    token: str
    client_id: str
    scopes: list[str]
    expires_at: int | None = None
