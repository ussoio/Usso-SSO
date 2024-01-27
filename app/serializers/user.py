from pydantic import BaseModel
from typing import Any
from app.serializers.auth import BaseAuth
from app.serializers.jwt_auth import JWTResponse


class UserSerializer(BaseModel):
    uid: str
    username: str | None
    authenticators: list[BaseAuth]
    links: list[str] = []
    data: dict[str, Any] = {}
    token: JWTResponse | None = None


class UserUpdate(BaseModel):
    username: str | None = None
