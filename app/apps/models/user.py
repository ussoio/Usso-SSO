"""User models."""

import asyncio
import base64
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Tuple

from apps.api_key.schemas import APIKeySchema
from apps.models import base
from apps.models.website import Website
from apps.util import password, sms, str_tools, utility
from beanie import Document
from pydantic import BaseModel, Field


class BasicAuthenticator(base.BaseDBModel):
    interface: str  # website url which user come from
    auth_method: base.AuthMethod = base.AuthMethod.email_password
    representor: str
    secret: bytes | None = None


class UserAuthenticator(BasicAuthenticator):
    data: dict[str, Any] = {}
    validated_at: datetime | None = None
    last_activity: datetime = datetime.now(timezone.utc)
    max_age_minutes: int | None = None

    def __init__(self, **kwargs):
        if (
            "secret" in kwargs
            and kwargs.get("auth_method", base.AuthMethod.email_password)
            == base.AuthMethod.email_password
            and kwargs.get("hash")
        ):
            kwargs["secret"] = password.hash_password(kwargs["secret"])

        super().__init__(**kwargs)

    async def __make_valid(self):
        self.validated_at = datetime.now(timezone.utc)
        self.last_activity = datetime.now(timezone.utc)
        # await self.update()

    async def validate(self, secret: str, **kwargs) -> bool:
        from server.db import redis_sync as redis

        if self.auth_method == base.AuthMethod.email_password:
            return bool(self.validated_at) and password.check_password(
                secret, self.secret
            )
        elif self.auth_method == base.AuthMethod.phone_otp:
            redis_otp = redis.get(f"OTP:{self.interface}:{self.representor}")
            if secret == redis_otp:
                await self.__make_valid()
                return True
        elif self.auth_method == base.AuthMethod.google:
            return True
        elif self.auth_method == base.AuthMethod.authenticator_app:
            # todo complete send_validation
            pass

        return False

    async def send_validation(self):
        if self.auth_method == base.AuthMethod.email_password:
            website = await Website.get_by_origin(self.interface)
            if website is None:
                return

            email_token = self.get_email_validation_token().decode("utf-8")
            temp_ua = UserAuthenticator(
                interface=self.interface,
                auth_method=base.AuthMethod.email_link,
                representor=self.representor,
                secret=email_token,
                hash=False,
                max_age_minutes=base.AuthMethod.email_link.max_age_minutes,
            )

            await website.send_verification_email(
                email=self.representor, token=email_token
            )
            return temp_ua
        elif self.auth_method == base.AuthMethod.email_link:
            website = await Website.get_by_origin(self.interface)
            if website is None:
                return

            email_token = self.get_email_validation_token().decode("utf-8")
            temp_ua = UserAuthenticator(
                interface=self.interface,
                auth_method=base.AuthMethod.email_link,
                representor=self.representor,
                secret=email_token,
                hash=False,
                max_age_minutes=base.AuthMethod.email_link.max_age_minutes,
            )

            await website.send_verification_email(
                email=self.representor, token=email_token
            )
            return temp_ua
        elif self.auth_method == base.AuthMethod.phone_otp:
            website = await Website.get_by_origin(self.interface)

            await self.send_otp(
                kavenegar_api_key=website.secrets.kavenegar_api_key,
                kavenegar_template=website.secrets.kavenegar_template,
            )
        elif self.auth_method == base.AuthMethod.google:
            self.__make_valid()
        elif self.auth_method == base.AuthMethod.authenticator_app:
            # todo complete send_validation
            pass

    def get_email_validation_token(self) -> str:
        assert self.auth_method in base.AuthMethod.email_methods()
        return base64.b64encode(
            f"{self.interface}:{self.representor}:{uuid.uuid4()}".encode("utf-8")
        )

    async def send_email(self, topic="verify"):
        assert self.auth_method in base.AuthMethod.email_methods()
        website = await Website.get_by_origin(self.interface)
        if website is None:
            return

        email_token = self.get_email_validation_token().decode("utf-8")
        temp_ua = UserAuthenticator(
            interface=self.interface,
            auth_method=base.AuthMethod.email_link,
            representor=self.representor,
            secret=email_token,
            hash=False,
            max_age_minutes=base.AuthMethod.email_link.max_age_minutes,
        )

        methods = {
            "verify": website.send_verification_email,
            "reset_password": website.send_reset_password_email,
            "email_otp": website.send_login_email,
        }

        await methods[topic](email=self.representor, token=email_token)

        return temp_ua

    async def send_otp(
        self,
        length=4,
        text=f"{{otp}}",
        timeout=5 * 60,
        test=False,
        **kwargs,
    ) -> str:
        from server.db import redis_sync as redis

        if self.auth_method != base.AuthMethod.phone_otp:
            return

        phone = self.representor
        self.secret = str_tools.generate_random_chars(length, "1234567890")
        if not test:
            await sms.send_sms_async(phone, text.format(otp=self.secret), **kwargs)
        redis.set(
            f"OTP:{self.interface}:{phone}:{self.secret}", self.secret, ex=timeout
        )
        return self.secret

    async def authenticate(self, secret: str, **kwargs) -> bool:
        from server.db import redis_sync as redis

        success = False
        if self.auth_method == base.AuthMethod.email_password:
            success = password.check_password(secret, self.secret)
        elif self.auth_method == base.AuthMethod.phone_otp:
            if secret is None:
                await self.send_otp()
                return False
            if type(secret) == bytes:
                redis_key = (
                    f"OTP:{self.interface}:{self.representor}:{secret.decode('utf-8')}"
                )
            else:
                redis_key = f"OTP:{self.interface}:{self.representor}:{secret}"

            success = redis.get(redis_key) == secret
            # redis.delete(redis_key)
        elif self.auth_method == base.AuthMethod.google:
            success = True
        elif self.auth_method == base.AuthMethod.authenticator_app:
            # todo complete authenticator app
            success = False

        if success:
            self.last_activity = datetime.now(timezone.utc)
            if self.validated_at is None and self.auth_method.valid_by_login():
                self.validated_at = datetime.now(timezone.utc)

        return success


class LoginSession(BaseModel):
    jti: str
    user_agent: str
    auth_method: base.AuthMethod
    login_at: datetime = datetime.now(timezone.utc)
    max_age_minutes: int | None = None
    ip: str
    location: str | None = None

    @property
    def expire_at(self) -> datetime:
        return self.login_at + timedelta(minutes=self.max_age_minutes)

    @property
    def is_expired(self) -> bool:
        return self.expire_at < datetime.now(timezone.utc)


class User(Document, base.BaseDBModel):
    name: str | None = None
    username: str | None = None
    website_uid: str | None = None
    workspace_id: str | None = None
    workspace_ids: list[str] = []
    authenticators: list[UserAuthenticator] = []
    current_authenticator: UserAuthenticator | None = Field(default=None, exclude=True)
    current_session: LoginSession | None = Field(default=None, exclude=True)
    last_activity: datetime = datetime.now(timezone.utc)
    is_active: bool = False
    login_sessions: list[LoginSession] = []
    data: dict[str, Any] = {}
    api_keys: dict[str, APIKeySchema] = {}
    history: list[dict[str, Any]] = []

    # auth: UserAuthenticator = field(init=False, default=None)  # type: ignore

    @property
    def user_id(self) -> uuid.UUID:
        from usso import b64tools

        user_id = self.uid

        if user_id.startswith("u_"):
            user_id = user_id[2:]
        if 22 <= len(user_id) <= 24:
            user_id = b64tools.b64_decode_uuid(user_id)

        return uuid.UUID(user_id)

    @property
    def b64id(self) -> uuid.UUID:
        from usso import b64tools

        return b64tools.b64_encode_uuid_strip(self.uid)

    class Settings:
        # use_cache = True
        # cache_expiration_time = timedelta(minutes=10)
        # cache_capacity = 1024

        indexes = [
            # Index for a field within each object in the 'authenticators' list
            [("authenticators.uid", 1)],
            # Index for a field within each object in the 'authenticators' list
            # IndexModel(
            #     [
            #         ("authenticators.interface", 1),
            #         ("authenticators.representor", 1),
            #         ("authenticators.auth_method", 1),
            #     ],
            #     unique=True,
            # ),
        ]

    @classmethod
    async def get_user_by_auth(
        cls,
        b_auth: BasicAuthenticator,
        **kwargs,
    ) -> Tuple["User", UserAuthenticator]:
        user = await cls.find_one(
            cls.authenticators.interface == b_auth.interface,
            cls.authenticators.representor == b_auth.representor,
            cls.authenticators.auth_method == b_auth.auth_method,
            # cls.authenticators.validated_at != None,
            cls.authenticators.is_deleted == False,
            cls.is_deleted == False,
        )
        if user is None:
            return None, None

        for auth in user.authenticators:
            if (
                auth.representor == b_auth.representor
                and auth.auth_method == b_auth.auth_method
                # and auth.validated_at is not None
                and auth.interface == b_auth.interface
            ):
                return user, auth
                # to check auth.max_age_minutes and send valid meessage for user
                if auth.max_age_minutes is None:
                    return user, auth
                if auth.last_activity + timedelta(
                    minutes=auth.max_age_minutes
                ) > datetime.now(timezone.utc):
                    return user, auth

        return None, None

    @classmethod
    async def login(
        cls,
        b_auth: BasicAuthenticator,
        **kwargs,
    ):
        user, auth = await cls.get_user_by_auth(b_auth, **kwargs)
        if user is None or auth is None:
            password.check_password(str_tools.generate_random_chars(4, "1234567890"))
            return None
        if not await auth.authenticate(b_auth.secret, **kwargs):
            return None

        if auth.auth_method.valid_by_login():
            user.is_active = True

        user.last_activity = datetime.now(timezone.utc)
        await user.save()
        user.current_authenticator = auth
        return user

    @classmethod
    async def register(
        cls,
        b_auth: BasicAuthenticator,
        **kwargs,
    ) -> tuple["User", bool]:
        created = False
        user, _ = await cls.get_user_by_auth(b_auth, **kwargs)
        if user is None:
            user = cls()
            created = True
            website = await Website.get_by_origin(b_auth.interface)
            if website.custom_claims:
                user.data = utility.fill_template(
                    website.custom_claims, user.model_dump()
                )

        user_auth = await user.add_authenticator(b_auth)

        # todo get data from authenticator
        # await user.save()
        user.current_authenticator = user_auth
        return user, created

    @property
    def jwt_payload(self) -> dict[str, Any]:
        """JWT payload fields."""
        # todo make it specific
        payload = self.model_dump()
        return payload

    async def add_authenticator(self, b_auth: BasicAuthenticator) -> UserAuthenticator:
        """Add an authenticator to user."""
        for i, auth in enumerate(self.authenticators):
            if (
                auth.representor == b_auth.representor
                and auth.auth_method == b_auth.auth_method
                and auth.interface == b_auth.interface
            ):
                if auth.max_age_minutes is not None:
                    if auth.last_activity + timedelta(
                        minutes=auth.max_age_minutes
                    ) < datetime.now(timezone.utc):
                        temp_ua = await auth.send_validation()
                        if temp_ua is not None:
                            self.authenticators[i] = temp_ua
                            await self.save()
                        return None

                if auth.validated_at:
                    if not self.is_active:
                        self.is_active = True
                        await self.save()
                    return auth

                if b_auth.secret is None or auth.auth_method.needs_validation():
                    temp_ua = await auth.send_validation()
                    if temp_ua is not None:
                        self.authenticators.append(temp_ua)
                        await self.save()
                    return None

                if await auth.validate(b_auth.secret):
                    self.last_activity = datetime.now(timezone.utc)
                    await self.save()
                    return auth

                return

        if type(b_auth) == UserAuthenticator:
            b_auth = BasicAuthenticator(**b_auth.model_dump())
        user_auth = UserAuthenticator(
            **b_auth.model_dump(),
            validated_at=(
                None if b_auth.auth_method.needs_validation() else datetime.now()
            ),
            hash=b_auth.auth_method.needs_secret(),
            max_age_minutes=b_auth.auth_method.max_age_minutes,
        )
        self.authenticators.append(user_auth)
        if user_auth.auth_method.needs_validation() and user_auth.validated_at is None:
            temp_ua = await user_auth.send_validation()
            if temp_ua is not None:
                self.authenticators.append(temp_ua)

        if not user_auth.auth_method.needs_validation():
            self.is_active = True

        await self.save()
        return user_auth

    async def merge(self, other: "User") -> None:
        """Merge two users.
        The worst case scenario is that both users has some activity on the
        other's website and has some records in their database
        """
        if self.uid == other.uid:
            return self
        if len(other.login_sessions) > len(self.login_sessions):
            return await other.merge(self)

        history = [self.model_dump()]
        for auth in other.authenticators:
            b_auth = BasicAuthenticator(**auth.model_dump())
            await self.add_authenticator(b_auth)

        history.append(other.model_dump())
        other.is_deleted = True
        await other.save()

        self.history = self.history + history
        self.last_activity = datetime.now(timezone.utc)
        await self.save()
        return self


if __name__ == "__main__":
    import asyncio

    from server import db

    async def main():
        await db.init_db()
        u_auth = BasicAuthenticator(
            interface="https://sso.bot.inbeet.tech",
            auth_method="email/password",
            representor="mahdikiany@gmail.com",
            secret="123456",
        )
        u = await User.login(u_auth)
        if u is None:
            u = await User.get_user_by_auth(u_auth)
            return u
            print("not exist")
            u = await User.register(u_auth)

        print(u.model_dump())
        return u
        await u.delete()

    u = asyncio.run(main())
