import re
import uuid
from datetime import datetime
from enum import Enum
from typing import Annotated, Optional

from beanie import Indexed
from fastapi_mongo_base.schemas import CoreEntitySchema
from pydantic import Field, model_validator


def abbreviate(text: str) -> str:
    return "".join(re.findall(r"[A-Z]", text)).lower()


def get_unique_id(cls) -> str:
    return f"{abbreviate(cls.__name__)}_{uuid.uuid4()}"


class BaseDBModel(CoreEntitySchema):
    uid: Annotated[str, Indexed(str, unique=True)] = Field(default="")
    data: dict = {}

    @model_validator(mode="before")
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
    def list(cls):
        return cls.find_all(not cls.is_deleted)

    @classmethod
    async def get_by_uid(cls, uid: str) -> Optional["BaseDBModel"]:
        item = await cls.find_one(cls.uid == uid, not cls.is_deleted)
        return item

    @classmethod
    async def exists_by_uid(cls, uid: str) -> bool:
        """Check if a model exists by uid."""
        return await cls.count(cls.uid == uid, not cls.is_deleted) > 0

    @classmethod
    async def delete_by_uid(cls, uid: str) -> None:
        """Check if a model exists by uid."""
        item = await cls.get_by_uid(uid)
        item.delete()


class AuthMethod(str, Enum):
    email_password = "email/password"
    email_link = "email/link"
    email_otp = "email/otp"
    user_password = "user/password"
    phone_otp = "phone/otp"
    phone_password = "phone/password"

    authenticator_app = "authenticator_app"
    qr = "qr"

    google = "google"
    oauth2 = "oauth2"
    telegram = "telegram"
    bale = "bale"
    app = "app"
    other = "other"

    @property
    def validation_regex(self):
        return {
            AuthMethod.email_password: r"^[a-zA-Z\._]+@[a-zA-Z0-9\.-_]+\.[a-zA-Z]{2,}$",
            AuthMethod.email_link: r"^[a-zA-Z\._]+@[a-zA-Z0-9\.-_]+\.[a-zA-Z]{2,}$",
            AuthMethod.email_otp: r"^[a-zA-Z\._]+@[a-zA-Z0-9\.-_]+\.[a-zA-Z]{2,}$",
            AuthMethod.user_password: r"^[a-zA-Z_][a-zA-Z0-9_]{2,16}$",
            AuthMethod.phone_otp: r"^(?:\+?98|0098|0|۹۸|۰۰۹۸|۰)9|۹[0-9۰-۹]{9}$",
            AuthMethod.phone_password: r"^(?:\+?98|0098|0|۹۸|۰۰۹۸|۰)9|۹[0-9۰-۹]{9}$",
        }.get(self)

    def get_secret_model(self, language: str = "fa"):
        from apps.schemas.config import SecretModel

        password_secret_dict = {
            "api": "/auth/login",
            "name": "password",
            "type": "password",
            "placeholder": "رمز عبور",
            "description": "رمز عبور خود را وارد کنید",
            "error": "رمز وارد شده صحیح نیست",
        }
        otp_secret_dict = {
            "api": "/auth/login",
            "name": "otp",
            "type": "otp",
            "placeholder": "کد ورود",
            "description": "کد ورود را اینجا وارد کنید",
            "error": "کد وارد شده صحیح نیست",
            "length": 4 if self.value == "phone/otp" else 6,
        }
        link_secret_dict = {
            "api": "/auth/login",
            "type": "link",
            "placeholder": "Link",
            "description": "Enter the login link",
        }

        secret_dict = {
            AuthMethod.email_password: password_secret_dict,
            AuthMethod.email_link: link_secret_dict,
            AuthMethod.email_otp: otp_secret_dict,
            AuthMethod.user_password: password_secret_dict,
            AuthMethod.phone_otp: otp_secret_dict,
            AuthMethod.phone_password: password_secret_dict,
        }

        return SecretModel(method=self.value, **secret_dict.get(self))

    @property
    def text(self):
        return {
            AuthMethod.google: "Sign in with Google",
        }.get(self)

    @property
    def icon(self):
        return {AuthMethod.google: "https://sso.usso.io/web/google.svg"}.get(self)

    @property
    def color(self):
        return {AuthMethod.google: "#4285F4"}.get(self)

    @property
    def auth_url(self):
        return {AuthMethod.google: "/auth/google"}.get(self)

    @classmethod
    def email_methods(cls) -> list["AuthMethod"]:
        return [
            AuthMethod.google,
            AuthMethod.email_password,
            AuthMethod.email_link,
            AuthMethod.email_otp,
        ]

    def needs_validation(self) -> bool:
        return self in {
            AuthMethod.user_password,
            AuthMethod.email_password,
            AuthMethod.phone_password,
            AuthMethod.authenticator_app,
        }

    @property
    def is_credential(self) -> bool:
        return self in {
            AuthMethod.email_password,
            AuthMethod.email_link,
            AuthMethod.email_otp,
            AuthMethod.user_password,
            AuthMethod.phone_otp,
            AuthMethod.phone_password,
        }

    @property
    def max_attempts(self) -> int:
        return 3 if self.needs_validation() else 0

    @property
    def max_age_minutes(self) -> int:
        return {
            AuthMethod.phone_otp: 5,
            AuthMethod.email_otp: 60,
            AuthMethod.email_link: 24 * 60,
        }.get(self)

    def needs_secret(self) -> bool:
        return self in {
            AuthMethod.email_password,
            AuthMethod.phone_password,
            AuthMethod.user_password,
        }

    def valid_by_login(self) -> bool:
        return self in {
            AuthMethod.google,
            AuthMethod.phone_otp,
            AuthMethod.authenticator_app,
            AuthMethod.email_link,
            AuthMethod.email_otp,
        }
