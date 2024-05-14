import json
import re
import uuid
from datetime import datetime
from enum import Enum
from typing import Annotated, Optional

from app.util import utility
from beanie import Indexed
from pydantic import BaseModel, Field, root_validator
from server.redis import redis


def abbreviate(text: str) -> str:
    return "".join(re.findall(r"[A-Z]", text)).lower()


def get_unique_id(cls) -> str:
    return f"{abbreviate(cls.__name__)}_{uuid.uuid4()}"


class BaseDBModel(BaseModel):
    uid: Annotated[str, Indexed(str, unique=True)] = Field(default="")
    #     default_factory=lambda: BaseDBModel.get_unique_id()
    # )
    created_at: datetime = datetime.utcnow()
    # updated_at: datetime = datetime.utcnow()
    is_deleted: bool = False
    data: dict = {}

    @root_validator(pre=True)
    def set_default_uid(cls, values):
        if "uid" not in values or values["uid"] is None:
            values["uid"] = get_unique_id(cls)
        return values

    @property
    def added(self) -> datetime | None:
        """Datetime user was created from ID."""
        return self.id.generation_time if self.id else None

    # @classmethod
    # def get_unique_id(cls) -> str:
    #     return f"{cls.__name__}_{str(uuid.uuid4())}"

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self}>"

    def __str__(self) -> str:
        return self.uid

    def __hash__(self) -> int:
        return hash(self.uid)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, BaseDBModel):
            return self.uid == other.uid
        return False

    @classmethod
    def list(cls) -> list["BaseDBModel"]:
        return cls.find_all(cls.is_deleted == False)

    @classmethod
    async def get_by_uid(cls, uid: str) -> Optional["BaseDBModel"]:
        """Get a model by uid."""
        redis_key = f"{cls.__name__}:{uid}"
        # item_str = redis.get(redis_key)
        # if item_str:
        #     return cls(**json.loads(item, object_hook=utility.json_deserializer))
        item = await cls.find_one(cls.uid == uid, cls.is_deleted == False)
        if not item:
            return None
        redis.set(
            redis_key,
            json.dumps(item.model_dump(), cls=utility.JSONSerializer),
            ex=60 * 20,
        )
        return item

    @classmethod
    async def exists_by_uid(cls, uid: str) -> bool:
        """Check if a model exists by uid."""
        return await cls.count(cls.uid == uid, cls.is_deleted == False) > 0

    @classmethod
    async def delete_by_uid(cls, uid: str) -> None:
        """Check if a model exists by uid."""
        item = await cls.get_by_uid(uid)
        item.delete()

    # async def delete(self) -> None:
    #     self.is_deleted = True
    #     redis.delete(f"{self.__class__.__name__}:{self.uid}")
    #     await self.update()

    # async def update(self) -> None:
    #     """Save a model."""
    #     self.updated_at = datetime.utcnow()
    #     await super().update()
    #     redis.set(f"{self.__class__.__name__}:{self.uid}", json.dumps(self.model_dump()))


class AuthMethod(str, Enum):
    google = "google"
    email_password = "email/password"
    phone_otp = "phone/otp"
    authenticator_app = "authenticator_app"
    email_link = "email/link"
    oauth2 = "oauth2"
    telegram = "telegram"
    other = "other"

    @classmethod
    def email_methods(cls) -> list["AuthMethod"]:
        return [AuthMethod.google, AuthMethod.email_password, AuthMethod.email_link]

    def needs_validation(self) -> bool:
        return self in (
            AuthMethod.email_password,
            AuthMethod.phone_otp,
            AuthMethod.authenticator_app,
        )

    @property
    def max_attempts(self) -> int:
        return 3 if self.needs_validation() else 0

    @property
    def max_age_minutes(self) -> int:
        return {
            AuthMethod.google: None,
            AuthMethod.email_password: None,
            AuthMethod.phone_otp: 5,
            AuthMethod.authenticator_app: None,
            AuthMethod.email_link: 24 * 60,
            AuthMethod.telegram: None,
            AuthMethod.oauth2: None,
            AuthMethod.other: None,
        }[self]

    def needs_secret(self) -> bool:
        return self in (AuthMethod.email_password,)

    def valid_by_login(self) -> bool:
        return self in (
            AuthMethod.google,
            AuthMethod.phone_otp,
            AuthMethod.authenticator_app,
            AuthMethod.email_link,
        )
