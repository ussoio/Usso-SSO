"""Auth response models."""

from datetime import timedelta

from pydantic import BaseModel

from app.middlewares.jwt_auth import ACCESS_EXPIRES, REFRESH_EXPIRES


class AccessToken(BaseModel):
    """Access token details."""

    access_token: str
    access_token_expires: timedelta = ACCESS_EXPIRES


class RefreshToken(AccessToken):
    """Access and refresh token details."""

    refresh_token: str
    refresh_token_expires: timedelta = REFRESH_EXPIRES
