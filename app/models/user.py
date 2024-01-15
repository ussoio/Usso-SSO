"""User models."""
import asyncio
import json
from datetime import datetime
from typing import Any

from app.models import base, website
from app.util import num_tools, password, sms, utility
from beanie import Document, Link
from pydantic import root_validator
from pymongo import IndexModel
from server.redis import redis


class BasicAuthenticator(base.BaseDBModel):
    # interface: Link[website.Website]  # website url which user come from
    interface: str  # website url which user come from
    auth_method: base.AuthMethod
    representor: str
    secret: bytes | None = None

    # @root_validator(pre=True)
    # def get_interface(cls, values):
    #     if type(values.get("interface")) == str:
    #         loop = asyncio.get_event_loop()
    #         values["interface"] = utility.run_async_in_thread(
    #             website.Website.get_by_origin
    #         )(values["interface"])

    #     return values


class UserAuthenticator(BasicAuthenticator):
    data: dict[str, Any] = {}
    validated_at: datetime | None = None
    last_activity: datetime = datetime.utcnow()

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
        self.validated_at = datetime.utcnow()
        self.last_activity = datetime.utcnow()
        # await self.update()

    async def validate(self):
        await self.__make_valid()

    async def send_validation(self):
        if self.auth_method == base.AuthMethod.email_password:
            # todo complete send_validation
            pass
        elif self.auth_method == base.AuthMethod.phone_otp:
            await self.send_otp()
        elif self.auth_method == base.AuthMethod.google:
            # todo complete send_validation
            pass
        elif self.auth_method == base.AuthMethod.authenticator_app:
            # todo complete send_validation
            pass

    async def send_otp(self) -> str:
        if self.auth_method != base.AuthMethod.phone_otp:
            return

        phone = self.representor
        self.secret = num_tools.generate_random_chars(4, "1234567890")
        sms.send_message(phone, f"Your OTP is {self.secret}")
        redis.set(f"OTP:{self.interface}:{phone}", self.secret, ex=5)
        return self.secret

    def authenticate(self, secret: str, **kwargs) -> bool:
        success = False
        if self.auth_method == base.AuthMethod.email_password:
            success = password.check_password(secret, self.secret)
        elif self.auth_method == base.AuthMethod.phone_otp:
            success = redis.get(f"OTP:{self.interface}:{self.representor}") == secret
        elif self.auth_method == base.AuthMethod.google:
            success = True
        elif self.auth_method == base.AuthMethod.authenticator_app:
            # todo complete authenticator app
            success = False

        if success:
            self.last_activity = datetime.utcnow()
            # self.update()
        return success


class User(Document, base.BaseDBModel):
    name: str | None = None
    username: str | None = None
    refresh_claim: str
    authenticators: list[UserAuthenticator] = []
    last_activity: datetime = datetime.utcnow()
    is_active: bool = False
    is_superuser: bool = False

    class Settings:
        indexes = [
            # Index for a field within each object in the 'authenticators' list
            [("authenticators.uid", 1)],
            # Index for a field within each object in the 'authenticators' list
            IndexModel(
                [
                    ("authenticators.interface", 1),
                    ("authenticators.representor", 1),
                    ("authenticators.auth_method", 1),
                ],
                unique=True,
            ),
        ]

    @root_validator(pre=True)
    def set_defaults(cls, values):
        values["refresh_claim"] = num_tools.generate_random_chars(8)
        return values

    @classmethod
    async def get_user_by_auth(
        cls,
        b_auth: BasicAuthenticator,
        **kwargs,
    ) -> ("User", UserAuthenticator):
        user = await cls.find_one(
            cls.authenticators.interface == b_auth.interface,
            cls.authenticators.representor == b_auth.representor,
            cls.authenticators.auth_method == b_auth.auth_method,
            cls.authenticators.validated_at != None,
            cls.authenticators.is_deleted == False,
            cls.is_deleted == False,
        )
        if user is None:
            return None, None

        for auth in user.authenticators:
            if (
                auth.representor == b_auth.representor
                and auth.auth_method == b_auth.auth_method
                and auth.validated_at is not None
                and auth.interface == b_auth.interface
            ):
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
            password.check_password(num_tools.generate_random_chars(4, "1234567890"))
            return None
        if not auth.authenticate(b_auth.secret, **kwargs):
            return None
        return user

    @classmethod
    async def register(
        cls,
        b_auth: BasicAuthenticator,
        **kwargs,
    ):
        user, _ = await cls.get_user_by_auth(b_auth, **kwargs)
        assert user is None, "User already exists"

        user = cls()
        await user.add_authenticator(b_auth)
        # todo get data from authenticator
        await user.save()
        return user

    async def validation(self) -> None:
        """Save user to redis."""
        return
        auth = self.authenticators[0]
        await auth.send_validation()
        redis.set(
            f"VALIDATION:{auth.interface}:{auth.representor}",
            json.dumps(self.model_dump(), cls=utility.JSONSerializer),
            ex=5 * 60,
        )

    @property
    def jwt_payload(self) -> dict[str, Any]:
        """JWT payload fields."""
        # todo make it specific
        payload = self.model_dump()
        return payload

    async def add_authenticator(self, b_auth: BasicAuthenticator) -> None:
        """Add an authenticator to user."""
        user_auth = UserAuthenticator(
            **b_auth.model_dump(),
            validated_at=None
            if b_auth.auth_method.needs_validation()
            else datetime.now(),
            hash=True,
        )
        self.authenticators.append(user_auth)
        if user_auth.auth_method.needs_validation() and user_auth.validated_at is None:
            await user_auth.send_validation()

        await self.save()

    async def merge(self, others: list["User"]) -> None:
        """Merge two users."""
        history = [self.model_dump()]
        for other in others:
            for auth in other.authenticators:
                await self.add_authenticator(auth)

            history.append(other.model_dump())
            other.is_deleted = True
            await other.save()
        self.data["history"] = history
        await self.save()


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
