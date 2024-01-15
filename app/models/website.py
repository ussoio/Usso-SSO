import json
import os
from typing import Annotated

import dotenv
from app.models import base
from app.util import num_tools, utility
from beanie import Document, Indexed
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import BaseModel, Field, root_validator
from server.redis import redis

dotenv.load_dotenv()


class Website(Document, base.BaseDBModel):
    origin: Annotated[str, Indexed(str, unique=True)]
    email_timeout: int = 60 * 60 * 24 * 7
    otp_timeout: int = 60 * 5
    otp_length: int = 4
    otp_message: str = "Your OTP is {otp}"
    email_message: str = (
        "Your email validation code is {code}"  # todo complete email message
    )
    rsa_priv: bytes
    rsa_pub: bytes
    api_key: str
    access_timeout: int = 60 * 10
    refresh_timeout: int = 60 * 60 * 24 * 30
    available_methods: list[base.AuthMethod] = [
        base.AuthMethod.google,
        base.AuthMethod.email_password,
    ]
    google_client_id: str | None = None
    google_client_secret: str | None = None
    
    @root_validator(pre=True)
    def set_defaults(cls, values):
        key = rsa.generate_private_key(
            backend=crypto_default_backend(), public_exponent=65537, key_size=2048
        )

        private_key = key.private_bytes(
            crypto_serialization.Encoding.PEM,
            crypto_serialization.PrivateFormat.PKCS8,
            encryption_algorithm=crypto_serialization.BestAvailableEncryption(
                os.getenv("RSA_PASSWORD", "password").encode("utf-8")
            ),
        )
        public_key = key.public_key().public_bytes(
            crypto_serialization.Encoding.OpenSSH,
            crypto_serialization.PublicFormat.OpenSSH,
        )

        values["rsa_priv"] = private_key
        values["rsa_pub"] = public_key
        values["api_key"] = f"sso-ak-{num_tools.generate_random_chars(32)}"
        return values

    @classmethod
    async def get_by_origin(cls, origin: str) -> "Website":
        redis_key = f"{cls.__name__}:{origin}"
        website = redis.get(redis_key)
        if website:
            return cls(**json.loads(website))
        website = await cls.find_one(cls.origin == origin)
        if not website:
            return None

        redis.set(
            redis_key,
            json.dumps(website.model_dump(), cls=utility.JSONSerializer),
            ex=60 * 60 * 24,
        )
        return website
