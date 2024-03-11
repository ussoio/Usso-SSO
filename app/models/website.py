import hashlib
import json
from datetime import timedelta
from typing import Annotated

import dotenv
import jwt
from app.models import base
from app.util import str_tools, utility
from beanie import Document, Indexed
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi_mail import ConnectionConfig, FastMail, MessageSchema, MessageType
from pydantic import BaseModel, EmailStr, root_validator
from server.config import CONFIG
from server.redis import redis

dotenv.load_dotenv()


class WebsiteConfig(base.BaseDBModel):
    name: str | None = None
    otp_timeout: int = 60 * 5
    otp_length: int = 4
    otp_message: str = "Your OTP is {otp}"
    email_timeout: int = 60 * 60 * 24 * 7
    # todo complete email message
    email_verification_template: str = "<br />\n".join(
        [
            "Welcome to {name}!",
            "We just need to verify your email. Click on the below link to begin:",
            "{url}",
        ]
    )
    email_reset_template: str = "<br />\n".join(
        [
            "Welcome to {name}!",
            "Someone have requested to reset password for your email address. Click on the below link to begin reset password or just ignore this email to do nothing:",
            "{url}",
        ]
    )
    email_login_template: str = "<br />\n".join(
        [
            "Welcome to {name}!",
            "Click on the below link to begin or just ignore this email to do nothing:",
            "{url}",
        ]
    )
    access_timeout: int = 60 * 10
    refresh_timeout: int = 60 * 60 * 24 * 30
    available_methods: list[base.AuthMethod] = [
        base.AuthMethod.google,
        base.AuthMethod.email_password,
    ]


class WebsiteSMTP(BaseModel):
    host: str
    port: int
    username: str
    password: str
    use_tls: bool = True
    use_ssl: bool = False
    sender: EmailStr

    @classmethod
    def from_env(cls):
        return cls(
            host=CONFIG.mail_server,
            port=CONFIG.mail_port,
            username=CONFIG.mail_username,
            password=CONFIG.mail_password,
            sender=CONFIG.mail_sender,
        )


class WebsiteSecrets(base.BaseDBModel):
    rsa_priv: bytes
    rsa_pub: bytes
    google_client_id: str | None = None
    google_client_secret: str | None = None
    smtp: WebsiteSMTP | None = WebsiteSMTP.from_env()

    @root_validator(pre=True)
    def set_defaults(cls, values):
        if "rsa_priv" in values and "rsa_pub" in values:
            return values

        key = rsa.generate_private_key(
            backend=crypto_default_backend(), public_exponent=65537, key_size=2048
        )

        private_key = key.private_bytes(
            crypto_serialization.Encoding.PEM,
            crypto_serialization.PrivateFormat.PKCS8,
            encryption_algorithm=crypto_serialization.BestAvailableEncryption(
                CONFIG.RSA_PASSWORD
            ),
        )
        public_key = key.public_key().public_bytes(
            crypto_serialization.Encoding.OpenSSH,
            crypto_serialization.PublicFormat.OpenSSH,
        )

        values["rsa_priv"] = private_key
        values["rsa_pub"] = public_key
        return values

    # @validator("smtp", pre=True)
    # def smtp_validator(cls, v):
    #     if v is None:
    #         return WebsiteSMTP.from_env()

    #     return WebsiteSMTP(**v)


class Website(Document, base.BaseDBModel):
    origin: Annotated[str, Indexed(str, unique=True)]
    api_key: Annotated[str, Indexed(str, unique=True)]
    user_uid: Annotated[str, Indexed(str)]
    config: WebsiteConfig = WebsiteConfig()
    secrets: WebsiteSecrets = WebsiteSecrets()
    custom_claims: dict = {}

    # class Settings:
    #     use_cache = True
    #     cache_expiration_time = timedelta(minutes=60)
    #     cache_capacity = 64

    @root_validator(pre=True)
    def set_defaults(cls, values):
        if not values.get("api_key"):
            values["api_key"] = f"sso-ak-{str_tools.generate_random_chars(32)}"
        return values

    @classmethod
    async def get_by_origin(cls, origin: str) -> "Website":
        redis_key = f"{cls.__name__}:{origin}"
        website = redis.get(redis_key)
        if website:
            return cls(**json.loads(website, object_hook=utility.json_deserializer))
        website = await cls.find_one(cls.origin == origin)
        if not website:
            website = await cls(origin=origin, user_id="123").save()
            # return website

        redis.set(
            redis_key,
            json.dumps(website.model_dump(), cls=utility.JSONSerializer),
            ex=60 * 60 * 24,
        )
        return website

    def get_mail_conf(self):
        if self.secrets.smtp:
            return {
                "MAIL_USERNAME": self.secrets.smtp.username,
                "MAIL_PASSWORD": self.secrets.smtp.password,
                "MAIL_FROM": self.secrets.smtp.sender,
                "MAIL_PORT": self.secrets.smtp.port,
                "MAIL_SERVER": self.secrets.smtp.host,
                "MAIL_STARTTLS": self.secrets.smtp.use_tls,
                "MAIL_SSL_TLS": self.secrets.smtp.use_ssl,
                "USE_CREDENTIALS": True,
            }
        return {
            "MAIL_USERNAME": CONFIG.mail_username,
            "MAIL_PASSWORD": CONFIG.mail_password,
            "MAIL_FROM": CONFIG.mail_sender,
            "MAIL_PORT": CONFIG.mail_port,
            "MAIL_SERVER": CONFIG.mail_server,
            "MAIL_STARTTLS": True,
            "MAIL_SSL_TLS": False,
            "USE_CREDENTIALS": True,
        }

    def get_mail(self):
        return FastMail(ConnectionConfig(**self.get_mail_conf()))

    async def __send_template_email(
        self, template: str, subject: str, email: str, **kwargs
    ) -> None:
        format_dict = self.config.model_dump()
        format_dict["name"] = (
            self.config.name if self.config.name else "User authentication service"
        )
        format_dict.update(**kwargs)
        mail_body = template.format(**format_dict)

        message = MessageSchema(
            recipients=[email],
            subject=subject,
            body=mail_body,
            subtype=MessageType.html,
        )

        if CONFIG.mail_console:
            print(message)
            # return
        await self.get_mail().send_message(message)

    async def send_login_email(self, email: str, token: str) -> None:
        url = f"https://{self.origin}/auth/login-token?token={token}"
        subject = (
            f"{self.config.name} Email Login" if self.config.name else "Email Login"
        )
        await self.__send_template_email(
            self.config.email_login_template, subject, email, url=url
        )

    async def send_verification_email(self, email: str, token: str) -> None:
        url = f"https://{self.origin}/auth/validate?token={token}"
        subject = (
            f"{self.config.name} Email Verification"
            if self.config.name
            else "Email Verification"
        )
        await self.__send_template_email(
            self.config.email_verification_template, subject, email, url=url
        )

    async def send_reset_password_email(self, email: str, token: str) -> None:
        url = f"https://{self.origin}/auth/reset-password?token={token}"
        subject = (
            f"{self.config.name} Password Reset"
            if self.config.name
            else "Password Reset"
        )
        await self.__send_template_email(
            self.config.email_reset_template, subject, email, url=url
        )

    def get_token(self, payload: dict) -> str:
        pem_bytes = self.secrets.rsa_priv
        private_key = crypto_serialization.load_pem_private_key(
            pem_bytes, password=CONFIG.RSA_PASSWORD, backend=crypto_default_backend()
        )

        if "data" in payload:
            data = payload.pop("data")
            payload.update(data)

        if "token_type" not in payload:
            raise ValueError("token_type not in payload")

        encoded = jwt.encode(
            payload,
            private_key,
            algorithm="RS256",
            headers={
                "kid": self.generate_kid(),
                "jwk_url": f"https://{self.origin}/website/jwks.json",
            },
        )
        return encoded

    def get_public_key(self) -> str:
        return crypto_serialization.load_ssh_public_key(
            self.secrets.rsa_pub, backend=crypto_default_backend()
        )

    def generate_kid(self) -> str:
        """Generates a Key ID (kid) for the JWKS."""
        public_key = self.get_public_key()
        der_public_key = public_key.public_bytes(
            encoding=crypto_serialization.Encoding.DER,
            format=crypto_serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        kid = hashlib.sha256(der_public_key).hexdigest()
        return kid

    def get_private_key(self) -> str:
        return crypto_serialization.load_pem_private_key(
            self.secrets.rsa_priv,
            password=CONFIG.RSA_PASSWORD,
            backend=crypto_default_backend(),
        )
