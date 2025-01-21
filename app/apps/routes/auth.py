"""Registration router."""

import hashlib
import hmac
import os
import uuid
from datetime import datetime, timedelta
from typing import Annotated

from apps.middlewares.auth import create_basic_authenticator
from apps.middlewares.jwt_auth import (
    get_email_secret_data_from_token,
    jwt_access_security_user,
    jwt_refresh_security,
    jwt_refresh_security_None,
    jwt_response,
)
from apps.models.base import AuthMethod
from apps.models.user import BasicAuthenticator, User, UserAuthenticator
from apps.models.website import Website
from apps.serializers.auth import BaseAuth, ForgetPasswordData, OTPAuth
from apps.serializers.jwt_auth import AccessToken
from apps.serializers.user import UserSerializer
from fastapi import APIRouter, Body, Depends, Query, Request, Response, Security
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi_mongo_base.core.exceptions import BaseHTTPException
from oauthlib.oauth2.rfc6749.errors import InvalidGrantError
from requests_oauthlib import OAuth2Session
from server.db import redis_sync as redis
from starlette.status import HTTP_201_CREATED

router = APIRouter(prefix="/auth", tags=["Register"])

embed = Body(..., embed=True)


@router.get("/", response_model=list[str])
async def get_all_route() -> list[str]:
    """Return all routes."""
    return [route.path for route in router.routes]


@router.post("/", response_model=UserSerializer)
async def add_auth(
    request: Request,
    response: Response,
    b_auth: BasicAuthenticator = Depends(create_basic_authenticator),
    user: User = Security(jwt_access_security_user),
) -> UserSerializer:
    """Return all routes."""
    existing_user, auth = await User.get_user_by_auth(b_auth)
    if existing_user is None:
        await user.add_authenticator(b_auth)
        return UserSerializer(**user.model_dump())

    if await auth.authenticate(b_auth.secret):
        user = await user.merge(existing_user)
        return UserSerializer(**user.model_dump())

    raise BaseHTTPException(403, "already_exists_wrong_secret")


@router.post("/register", response_model=UserSerializer)
async def user_registration(
    request: Request,
    response: Response,
    b_auth: BasicAuthenticator = Depends(create_basic_authenticator),
) -> UserSerializer:  # type: ignore[no-untyped-def]
    """Create a new user."""
    user, success = await User.register(b_auth)
    if not success:
        if user.is_active:
            raise BaseHTTPException(409, "already_exists")
        raise BaseHTTPException(409, "not_active")

    response.status_code = HTTP_201_CREATED
    token = await jwt_response(user, request, response, refresh=True)
    return UserSerializer(token=token, **user.model_dump())


@router.post("/1st-step")
async def step1(
    request: Request,
    response: Response,
    data: dict = Body(),
):
    if "phone" in data:
        return await phone_otp_request(request, response, phone=data["phone"])


@router.post("/login")
async def login(
    request: Request,
    response: Response,
    b_auth: BasicAuthenticator = Depends(create_basic_authenticator),
) -> UserSerializer:  # type: ignore[no-untyped-def]
    """Authenticate and returns the user's JWT."""
    user = await User.login(b_auth)
    if user is None:
        raise BaseHTTPException(401, "unauthorized", language="fa")
    token = await jwt_response(user, request, response, refresh=True)
    return UserSerializer(token=token, **user.model_dump())


@router.post("/refresh")
async def refresh(
    request: Request,
    response: Response,
    user: User = Security(jwt_refresh_security),
) -> AccessToken:
    """Return a new access token from a refresh token."""
    token = await jwt_response(user, request, response, refresh=False)
    return AccessToken(**token.model_dump())


@router.get("/refresh")
async def refresh(
    request: Request,
    response: Response,
    user: User = Security(jwt_refresh_security),
) -> AccessToken:
    """Return a new access token from a refresh token."""
    token = await jwt_response(user, request, response, refresh=False)
    return AccessToken(**token.model_dump())


@router.post("/phone-otp-request")
async def phone_otp_request(
    request: Request,
    response: Response,
    test: bool = False,
    phone: str = Body(embed=True),
) -> JSONResponse:
    """Send OTP to phone using sms."""
    website = await Website.get_by_origin(request.url.hostname)
    b_auth = create_basic_authenticator(request, OTPAuth(phone=phone))
    _, auth = await User.get_user_by_auth(b_auth)

    if not auth:
        user, success = await User.register(b_auth)
        auth = user.current_authenticator

    otp = await auth.send_otp(
        length=website.config.otp_length,
        text=website.config.otp_message,
        timeout=website.config.otp_timeout,
        test=test,
        kavenegar_api_key=website.secrets.kavenegar_api_key,
        kavenegar_template=website.secrets.kavenegar_template,
    )

    return JSONResponse(
        {"message": f"کد ورود برای شماره‌ی شما پیامک شد.", "length": len(otp)},
        status_code=200,
    )
    # response.status_code = HTTP_201_CREATED
    # token = await jwt_response(user, request, response, refresh=True)
    # return UserSerializer(token=token, **user.model_dump())


@router.post("/login-otp")
async def login_otp(
    request: Request,
    response: Response,
    otp_auth: OTPAuth,
) -> JSONResponse:
    """Send OTP to phone using sms."""
    b_auth = create_basic_authenticator(request, otp_auth)
    return await login(request, response, b_auth)


@router.post("/email-otp-request")
async def email_otp(
    request: Request,
    user_auth: ForgetPasswordData,
) -> JSONResponse:
    """Send otp login email."""
    b_auth = create_basic_authenticator(request, BaseAuth(representor=user_auth.email))
    user, auth = await User.get_user_by_auth(b_auth)
    if user is None:
        raise BaseHTTPException(404, "no_user")

    t_auth = await auth.send_email(topic="email_otp")
    await user.add_authenticator(t_auth)
    await user.save()

    return JSONResponse({"message": "login email has sent"}, status_code=200)


@router.post("/forgot-password")
async def forgot_password(
    request: Request,
    user_auth: ForgetPasswordData,
    # user=Security(jwt_refresh_security_None),
) -> JSONResponse:
    """Send password reset email."""
    b_auth = create_basic_authenticator(request, BaseAuth(representor=user_auth.email))
    user, auth = await User.get_user_by_auth(b_auth)
    if user is None:
        raise BaseHTTPException(404, "no_user")

    t_auth = await auth.send_email(topic="reset_password")
    await user.add_authenticator(t_auth)
    await user.save()

    return JSONResponse({"message": "reset password email has sent"}, status_code=200)


@router.post("/reset-password", response_model=UserSerializer)
async def reset_password(
    request: Request, response: Response, token: str, password: str = embed
) -> UserSerializer:
    """Reset user password from token value."""
    origin, token_email, token_secret = get_email_secret_data_from_token(token)
    b_auth = BasicAuthenticator(
        interface=origin,
        auth_method=AuthMethod.email_link,
        representor=token_email,
        secret=token_secret,
    )
    user, auth = await User.get_user_by_auth(b_auth)
    if user is None:
        raise BaseHTTPException(404, "no_user")
    if auth.max_age_minutes is not None and (
        auth.created_at + timedelta(minutes=auth.max_age_minutes) < datetime.utcnow()
    ):
        raise BaseHTTPException(404, "link_expired")

    user.authenticators.remove(auth)
    for auth in user.authenticators:
        if (
            auth.interface == b_auth.interface
            and auth.auth_method == AuthMethod.email_password
            and auth.representor == token_email
        ):
            user.authenticators.remove(auth)

    auth = UserAuthenticator(
        interface=b_auth.interface,
        representor=token_email,
        secret=password,
        validated_at=datetime.utcnow(),
    )

    user.is_active = True
    await user.add_authenticator(auth)

    token = await jwt_response(user, request, response, refresh=True)
    return UserSerializer(token=token, **user.model_dump())


@router.get("/validate", response_model=UserSerializer)
async def validate(request: Request, response: Response, token: str):  # type: ignore[no-untyped-def]
    """Reset user password from token value."""
    origin, token_email, token_secret = get_email_secret_data_from_token(token)
    b_auth = BasicAuthenticator(
        interface=origin,
        auth_method=AuthMethod.email_link,
        representor=token_email,
        secret=token_secret,
    )
    user, auth = await User.get_user_by_auth(b_auth)
    if user is None:
        raise BaseHTTPException(404, "no_user")
    if auth.max_age_minutes is not None and (
        auth.created_at + timedelta(minutes=auth.max_age_minutes) < datetime.utcnow()
    ):
        raise BaseHTTPException(404, "link_expired")

    user.authenticators.remove(auth)
    for auth in user.authenticators:
        if (
            auth.interface == b_auth.interface
            and auth.auth_method == AuthMethod.email_password
            and auth.representor == token_email
        ):
            if auth.validated_at is None:
                auth.validated_at = datetime.utcnow()

    user.is_active = True
    await user.save()

    token = await jwt_response(user, request, response, refresh=True)
    return UserSerializer(token=token, **user.model_dump())


@router.get("/login-token")
async def login_token(
    request: Request, response: Response, token: str
) -> UserSerializer:  # type: ignore[no-untyped-def]
    """Authenticate and returns the user's JWT."""
    origin, token_email, token_secret = get_email_secret_data_from_token(token)
    b_auth = BasicAuthenticator(
        interface=origin,
        auth_method=AuthMethod.email_link,
        representor=token_email,
        secret=token_secret,
    )
    user, auth = await User.get_user_by_auth(b_auth)
    if user is None:
        raise BaseHTTPException(404, "no_user")
    if auth.max_age_minutes is not None and (
        auth.created_at + timedelta(minutes=auth.max_age_minutes) < datetime.utcnow()
    ):
        raise BaseHTTPException(404, "link_expired")

    user.authenticators.remove(auth)
    user.is_active = True
    await user.save()

    token = await jwt_response(user, request, response, refresh=True)
    return UserSerializer(token=token, **user.model_dump())


@router.get("/google")
async def google_login(request: Request, callback: str | None = None):
    """Google login."""
    origin = request.url.hostname
    website = await Website.get_by_origin(origin)
    if website is None:
        raise BaseHTTPException(404, "no_website")

    client_id = website.secrets.google_client_id
    import logging

    logging.info(client_id)
    # secret = website.secrets.google_client_secret
    redirect_uri = f"https://{origin}/auth/google-callback"

    scopes = [
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",
        "openid",
    ]
    oauth = OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scopes)
    authorization_url, state = oauth.authorization_url(
        "https://accounts.google.com/o/oauth2/auth",
        # access_type and prompt are Google specific extra
        # parameters.
        access_type="offline",
        prompt="select_account",
    )

    if callback:
        redis.set(f"google-callback:{state}", callback, ex=60 * 60 * 24 * 7)

    response = RedirectResponse(url=authorization_url)

    return response


@router.get("/google-callback")
async def google_login_callback(
    request: Request,
    response: Response,
    logged_in_user=Depends(jwt_refresh_security_None),
):
    """Google login."""
    try:
        origin = request.url.hostname
        website = await Website.get_by_origin(origin)
        if website is None:
            raise BaseHTTPException(404, "no_website")

        client_id = website.secrets.google_client_id
        client_secret = website.secrets.google_client_secret

        redirect_uri = f"https://{origin}/auth/google-callback"
        scopes = [
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile",
            "openid",
        ]
        oauth = OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scopes)

        url = str(request.url).replace("http:", "https:")
        token = oauth.fetch_token(
            "https://accounts.google.com/o/oauth2/token",
            authorization_response=url,
            # Google specific extra parameter used for client
            # authentication
            client_secret=client_secret,
        )

        oauth_userinfo_resp = oauth.get("https://www.googleapis.com/oauth2/v1/userinfo")

        user_data = oauth_userinfo_resp.json()
    except InvalidGrantError:
        raise BaseHTTPException(400, "oath_failed")
    except Exception as e:
        raise BaseHTTPException(400, "error", str(e))

    state = request.query_params.get("state")
    callback = redis.get(f"google-callback:{state}")
    if callback:
        redis.delete(f"google-callback:{state}")
        callback = callback.decode("utf-8")

    g_auth = BasicAuthenticator(
        interface=origin,
        auth_method=AuthMethod.google,
        representor=user_data["email"],
    )

    # user, auth = await User.get_user_by_auth(g_auth)
    user = await User.login(g_auth)
    if user:
        if logged_in_user:
            user = await logged_in_user.merge(user)

        if callback:
            response = RedirectResponse(url=callback)
            token = await jwt_response(user, request, response, refresh=True)
            return response

        # user.current_authenticator = auth
        token = await jwt_response(user, request, response, refresh=True)
        return UserSerializer(**user.model_dump(), token=token)

    b_auth = BasicAuthenticator(
        interface=origin,
        auth_method=AuthMethod.email_password,
        representor=user_data["email"],
    )

    user, auth = await User.get_user_by_auth(b_auth)
    if user:
        if logged_in_user:
            user = await logged_in_user.merge(user)

        gu_auth = await user.add_authenticator(g_auth)
        gu_auth.data = user_data

        if auth.validated_at is None:
            auth.validated_at = datetime.utcnow()

        user.is_active = True
        user.authenticators[-1].data = user_data
        user.current_authenticator = gu_auth
        await user.save()

        if callback:
            response = RedirectResponse(url=callback)
            token = await jwt_response(user, request, response, refresh=True)
            return response

        token = await jwt_response(user, request, response, refresh=True)
        return UserSerializer(**user.model_dump(), token=token)

    if logged_in_user is None:
        user, created = await User.register(g_auth)
    else:
        user = logged_in_user

    gu_auth = await user.add_authenticator(g_auth)
    gu_auth.data = user_data
    user.authenticators[-1].data = user_data
    user.current_authenticator = gu_auth
    await user.save()

    if callback:
        response = RedirectResponse(url=callback)
        token = await jwt_response(user, request, response, refresh=True)
        return response

    token = await jwt_response(user, request, response, refresh=True)
    return UserSerializer(**user.model_dump(), token=token)


@router.get("/telegram")
async def telegram_login(request: Request, callback: str | None = None):
    origin = request.url.hostname
    website = await Website.get_by_origin(origin)
    if website is None:
        raise BaseHTTPException(404, "no_website")

    redirect_uri = f"https://sso.usso.io/auth/telegram-callback"
    return HTMLResponse(
        f'<html><body><script async src="https://telegram.org/js/telegram-widget.js?22" data-telegram-login="usso_auth_bot" data-size="large" data-auth-url="{redirect_uri}" data-request-access="write"></script></body></html>'
    )


@router.get("/telegram-callback")
async def telegram_callback(
    request: Request,
    response: Response,
    user_id: Annotated[int, Query(alias="id")],
    query_hash: Annotated[str, Query(alias="hash")],
    logged_in_user=Depends(jwt_refresh_security_None),
):
    origin = request.url.hostname
    website = await Website.get_by_origin(origin)
    if website is None:
        raise BaseHTTPException(404, "no_website")

    params = request.query_params.items()
    data_check_string = "\n".join(
        sorted(f"{x}={y}" for x, y in params if x not in ("hash", "next"))
    )
    BOT_TOKEN_HASH = hashlib.sha256(os.getenv("TELEGRAM_BOT_TOKEN").encode())
    computed_hash = hmac.new(
        BOT_TOKEN_HASH.digest(), data_check_string.encode(), "sha256"
    ).hexdigest()
    is_correct = hmac.compare_digest(computed_hash, query_hash)
    if not is_correct:
        raise BaseHTTPException(400, "oath_failed")

    if logged_in_user is None:
        t_auth = BasicAuthenticator(
            interface=origin,
            auth_method=AuthMethod.telegram,
            representor=f"{user_id}",
            data=request.query_params,
        )
        user, created = await User.register(t_auth)
    else:
        user = logged_in_user

    # return HTMLResponse(
    #     f'<html><body><img src="{request.query_params.get("photo_url")}" /></body></html>'
    # )

    token = await jwt_response(user, request, response, refresh=True)
    return UserSerializer(**user.model_dump(), token=token)


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    jti: str = embed,
    user=Depends(jwt_refresh_security_None),
):
    """Logout."""
    if user:
        for session in user.login_sessions:
            if session.jti == jti:
                user.login_sessions.remove(session)
                break
        await user.save()

    origin = request.url.hostname
    parent_domain = ".".join(origin.split(".")[1:])

    response.delete_cookie("usso_access_available", domain=parent_domain, secure=True)
    response.delete_cookie("usso_access_token", domain=parent_domain, secure=True)
    response.delete_cookie("usso_user_id", domain=parent_domain, secure=True)
    response.delete_cookie("usso_refresh_available", domain=parent_domain, secure=True)
    response.delete_cookie("usso_refresh_token", secure=True)

    return JSONResponse({"message": f"{jti} session logged out"}, status_code=200)


@router.get("/logout")
async def logout(
    request: Request,
    response: Response,
    user=Depends(jwt_refresh_security_None),
):
    """Logout."""
    if user:
        user.login_sessions.remove(user.current_session)
        await user.save()

    origin = request.url.hostname
    parent_domain = ".".join(origin.split(".")[1:])

    if request.query_params.get("callback"):
        response = RedirectResponse(url=request.query_params.get("callback"))
    else:
        response = JSONResponse({"message": "logged out"}, status_code=200)

    response.delete_cookie("usso_access_available", domain=parent_domain, secure=True)
    response.delete_cookie("usso_access_token", domain=parent_domain, secure=True)
    response.delete_cookie("usso_refresh_available", domain=parent_domain, secure=True)
    response.delete_cookie("usso_refresh_token", secure=True)

    return response


@router.get("/refresh/api")
async def get_token(request: Request, response: Response, user_id: uuid.UUID = None):
    import logging

    from .website import get_website

    website = await get_website(request)

    logging.info(f"refresh admin api key {website.origin} {user_id}")

    user_id = f"u_{user_id}" if user_id else website.user_uid
    user = await User.find_one(User.uid == user_id)
    if not user:
        raise BaseHTTPException(404, "user_not_found")
    token = await jwt_response(user, request, response, refresh=True)
    return UserSerializer(token=token, **user.model_dump())


@router.get("/cookies", include_in_schema=False)
async def cookies(request: Request):
    return dict(request.cookies)


@router.get("/long-token", include_in_schema=False)
async def cookies(
    request: Request,
    response: Response,
    days: int = 30,
    user: User = Depends(jwt_access_security_user),
):
    token = await jwt_response(user, request, response, days=days, refresh=False)
    return AccessToken(**token.model_dump())
