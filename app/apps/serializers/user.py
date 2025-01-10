from datetime import datetime
from typing import Any

from pydantic import BaseModel

from apps.serializers.auth import BaseAuth
from apps.serializers.jwt_auth import JWTResponse


class UserSerializer(BaseModel):
    uid: str
    username: str | None
    authenticators: list[BaseAuth]
    links: list[str] = []
    data: dict[str, Any] = {}
    created_at: datetime | None = None
    token: JWTResponse | None = None


class UserUpdate(BaseModel):
    username: str | None = None
