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
    updated_at: datetime = datetime.utcnow()
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
    async def list(cls) -> list["BaseDBModel"]:
        return cls.find_all(cls.is_deleted == False)

    @classmethod
    async def get_by_uid(cls, uid: str) -> Optional["BaseDBModel"]:
        """Get a model by uid."""
        item = redis.get(f"{cls.__name__}:{uid}")
        if item:
            return cls(**json.loads(item))
        item = await cls.find_one(cls.uid == uid, cls.is_deleted == False)
        redis.set(
            f"{cls.__name__}:{uid}",
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

    def needs_validation(self) -> bool:
        return self in (
            AuthMethod.email_password,
            AuthMethod.phone_otp,
            AuthMethod.authenticator_app,
        )

    def needs_secret(self) -> bool:
        return self in (AuthMethod.email_password,)
