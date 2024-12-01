from datetime import datetime

from fastapi_mongo_base.schemas import OwnedEntitySchema
from pydantic import Field
from usso import UserData


class APIKeySchema(OwnedEntitySchema):
    hashed_key: bytes
    api_key_pattern: str
    postfix: str
    scopes: list[str] = []
    is_active: bool = True  # Status of the key
    expires_at: datetime | None = None  # Optional expiration date
    last_used_at: datetime | None = None  # Last time the key was used


class APIKeyResponseSchema(OwnedEntitySchema):
    api_key_pattern: str
    postfix: str
    scopes: list[str] = []
    is_active: bool = True  # Status of the key
    expires_at: datetime | None = None  # Optional expiration date
    last_used_at: datetime | None = None  # Last time the key was used


class APIKeyCreateResponseSchema(APIKeyResponseSchema):
    api_key: str = Field(..., description="The API key")


class APIKeyVerifySchema(UserData):
    scopes: list[str] = []
    # user_id: str = Field(..., description="The user id")

    # workspace_id: str | None = None
    # workspace_ids: list[str] = []
    # token_type: str = "access"

    # email: str | None = None
    # phone: str | None = None
    # username: str | None = None

    # authentication_method: str = "api_key"
    # is_active: bool = True

    # data: dict | None = None
