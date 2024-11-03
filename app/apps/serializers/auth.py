from apps.models.base import AuthMethod
from apps.util import password, str_tools
from pydantic import BaseModel, EmailStr, field_validator


class BaseAuth(BaseModel):
    auth_method: AuthMethod = AuthMethod.email_password
    representor: str


class Auth(BaseAuth):
    secret: bytes | None = None


class ForgetPasswordData(BaseModel):
    email: EmailStr

    @field_validator("email")
    def validate_email(cls, v):
        return str_tools.email_validator(v)


class EmailAuth(BaseModel):
    email: EmailStr
    password: str

    @field_validator("email")
    def validate_email(cls, v):
        return str_tools.email_validator(v)

    @field_validator("password", mode="before")
    def validate_password(cls, v):
        errors = password.check_password_strength(v)
        if errors:
            err_key = errors[0] if len(errors) == 1 else "password_multiple_errors"
            # raise BaseHTTPException(
            #     400, err_key, ".\n".join([err[1] for err in errors])
            # )
            raise ValueError(".\n".join([err[1] for err in errors]))
        return v


class OTPAuth(BaseModel):
    phone: str
    otp: str | None = None

    @field_validator("phone", mode="before")
    def validate_phone(cls, v):
        v = str_tools.convert_to_english_digits(v)
        if not str_tools.is_valid_mobile(v):
            raise ValueError("phone number is not valid")
        v = str_tools.format_mobile(v)
        return v

    @field_validator("otp", mode="before")
    def validate_otp(cls, v):
        v = str_tools.convert_to_english_digits(v)
        return v


class GoogleAuth(BaseModel):
    code: str


class AuthenticatorAuth(BaseModel):
    authenticator: str
    code: str
