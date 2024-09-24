import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class JWTMode(str, Enum):
    ACCESS = "access"
    REFRESH = "refresh"


class UserData(BaseModel):
    user_id: str
    email: str | None = None
    phone: str | None = None
    authentication_method: str | None = None
    is_active: bool = False
    jti: str


class JWTPayload(BaseModel):
    user_id: str
    iat: int = Field(default_factory=lambda: int(datetime.utcnow().timestamp()))
    exp: int | None = None
    jti: str = Field(default_factory=lambda: f"jti_{uuid.uuid4()}")
    # origin: str = Field(exclude=True)
    # jwks_uri: str = "/website/jwks.json"
    # jwk_url: str | None = None
    token_type: str = JWTMode.ACCESS.value
    data: dict[str, Any] = {}

    email: str | None = None
    phone: str | None = None
    authentication_method: str | None = None
    is_active: bool = False

    scopes: list[str] | None = None
    app_id: str | None = None

    # @model_validator(mode="before")
    # def validate_data(cls, values):
    #     if values.get("jwk_url") is None:
    #         values["jwk_url"] = "https://" + (
    #             f'{values["origin"]}/website/jwks.json'
    #         ).replace("https://", "").replace("//", "/")

    #     return values

    @field_validator("exp", mode="before")
    def convert_datetime_to_timestamp(cls, v):
        if v is None:
            return int(datetime.utcnow().timestamp()) + 60
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
