from pydantic import BaseModel

from app.serializers.auth import BaseAuth
from app.serializers.jwt_auth import JWTResponse


class UserSerializer(BaseModel):
    uid: str
    username: str | None
    authenticators: list[BaseAuth]
    links: list[str] = []
    token: JWTResponse | None = None


class UserUpdate(BaseModel):
    username: str | None = None
