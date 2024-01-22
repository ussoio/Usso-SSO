from pydantic import BaseModel, Field

from app.models import base


class WebsiteSerializer(BaseModel):
    uid: str
    origin: str
    links: list[str]


class WebsiteAPIKeySerializer(WebsiteSerializer):
    api_key: str
    user_uid: str


class WebsiteConfigSerializer(BaseModel):
    otp_timeout: int
    otp_length: int
    otp_message: str
    email_timeout: int
    email_verification_template: str
    email_reset_template: str
    access_timeout: int
    refresh_timeout: int
    available_methods: list[base.AuthMethod]
    links: list[str]


class WebsiteSecretsSerializer(BaseModel):
    rsa_pub: bytes
    google_client_id: str | None = None
    google_client_secret: str | None = None
    links: list[str]


class RSAJWK(BaseModel):
    kty: str = Field(..., description="Key Type")
    use: str = Field(..., description="Public Key Use")
    alg: str = Field(..., description="Algorithm")
    n: str = Field(..., description="Modulus")
    e: str = Field(..., description="Exponent")


class JWKS(BaseModel):
    keys: list[RSAJWK]
