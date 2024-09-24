from fastapi import HTTPException, Request

from apps.models.base import AuthMethod
from apps.models.user import BasicAuthenticator
from apps.serializers.auth import (
    AuthenticatorAuth,
    BaseAuth,
    EmailAuth,
    GoogleAuth,
    OTPAuth,
)


def create_basic_authenticator(
    request: Request,
    user_auth: BaseAuth | EmailAuth | OTPAuth | GoogleAuth | AuthenticatorAuth,
) -> BasicAuthenticator:
    origin = request.url.hostname
    if user_auth is None:
        raise HTTPException(401, "Invalid credentials")
    if type(user_auth) == EmailAuth:
        return BasicAuthenticator(
            interface=origin,
            auth_method=AuthMethod.email_password,
            representor=user_auth.email,
            secret=user_auth.password,
        )
    if type(user_auth) == OTPAuth:
        return BasicAuthenticator(
            interface=origin,
            auth_method=AuthMethod.phone_otp,
            representor=user_auth.phone,
            secret=user_auth.otp,
        )
    if type(user_auth) == GoogleAuth:
        return BasicAuthenticator(
            interface=origin,
            auth_method=AuthMethod.google,
            representor="",
            secret=user_auth.code,
        )
    if type(user_auth) == AuthenticatorAuth:
        return BasicAuthenticator(
            interface=origin,
            auth_method=AuthMethod.authenticator_app,
            representor=user_auth.authenticator,
            secret=user_auth.code,
        )
    # google
    # authenticator_app

    return BasicAuthenticator(interface=origin, **user_auth.model_dump())
