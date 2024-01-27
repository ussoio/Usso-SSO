import uuid
from datetime import datetime
from enum import Enum
from typing import Any
from pydantic import BaseModel, Field, validator


class JWTMode(str, Enum):
    ACCESS = "access"
    REFRESH = "refresh"


class UserData(BaseModel):
    user_id: str
    origin: str
    email: str | None = None
    phone: str | None = None
    authentication_method: str | None = None
    is_active: bool = False
    jti: str


class JWTPayload(BaseModel):
    user_id: str
    iat: int = Field(default_factory=lambda: int(datetime.utcnow().timestamp()))
    exp: int
    jti: str = Field(default_factory=lambda: f"jti_{uuid.uuid4()}")
    origin: str
    jwks_uri: str = "/website/jwks.json"
    token_type: str
    data: dict[str, Any] = {}

    email: str | None = None
    phone: str | None = None
    authentication_method: str | None = None
    is_active: bool = False

    @validator("exp", pre=True)
    def convert_datetime_to_timestamp(cls, v):
        if isinstance(v, datetime):
            return int(v.timestamp())
        return v


class AccessPayload(JWTPayload):
    token_type: str = JWTMode.ACCESS.value


class RefreshPayload(JWTPayload):
    token_type: str = JWTMode.REFRESH.value


class JWKS(BaseModel):
    key: bytes


class AccessToken(BaseModel):
    access_token: str | None = None


class JWTResponse(BaseModel):
    access_token: str | None = None
    refresh_token: str | None = None


class JWTRefresh(BaseModel):
    refresh_token: str | None = None
