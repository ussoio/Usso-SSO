"""FastAPI JWT configuration."""

import base64
from datetime import UTC, datetime, timedelta
from typing import Optional, Tuple

import aiohttp
import jwt
from apps.models.base import AuthMethod
from apps.models.user import LoginSession, User
from apps.models.website import Website
from apps.serializers.jwt_auth import (
    JWTMode,
    JWTPayload,
    JWTRefresh,
    JWTResponse,
    UserData,
)
from core.exceptions import BaseHTTPException
from fastapi import Request, Response
from starlette.status import HTTP_401_UNAUTHORIZED

# from fastapi_jwt import JwtAuthorizationCredentials, JwtAccessBearer, JwtRefreshBearer


async def get_token(user: User, website: Website, token_type: JWTMode, **kwargs) -> str:
    """Return the user associated with a token value."""
    phone = None
    email = None

    for auth in user.authenticators:
        if auth.auth_method == AuthMethod.phone_otp:
            phone = auth.representor
        elif auth.auth_method == AuthMethod.email_password:
            email = auth.representor
        elif auth.auth_method == AuthMethod.google:
            email = auth.representor

    payload = JWTPayload(
        user_id=user.uid,
        exp=datetime.now(UTC)
        + timedelta(
            seconds=(
                website.config.access_timeout
                if token_type == JWTMode.ACCESS
                else website.config.refresh_timeout
            )
        ),
        # origin=website.origin,
        # jwk_url=f'https://{website.origin}/website/jwks.json',
        token_type=token_type.value,
        email=email,
        phone=phone,
        is_active=user.is_active,
        authentication_method=user.current_authenticator.auth_method,
        data=user.data,
        **kwargs,
    )

    return website.get_token(payload.model_dump(exclude_none=True))


async def answer_jwt_in_cookie(request: Request):
    user_agent = request.headers.get("user-agent")
    has_cookie = bool(request.cookies)
    if user_agent is None and not has_cookie:
        return False

    if "Mozilla" in user_agent or "Chrome" in user_agent or "Safari" in user_agent:
        return True
    if has_cookie:
        return True

    return False


async def get_location(ip_address):
    async with aiohttp.ClientSession() as session:
        async with session.get(f"https://ipapi.co/{ip_address}/json/") as response:
            if response.status == 200:
                data = await response.json()
                location_data = {
                    "ip": ip_address,
                    "city": data.get("city"),
                    "region": data.get("region"),
                    "country": data.get("country_name"),
                    "location": f'{data.get("country_name", "")}, {data.get("region", "")}, {data.get("city", "")}',
                    "latitude": data.get("latitude"),
                    "longitude": data.get("longitude"),
                }
                return location_data
            else:
                return {"error": "Failed to get location data"}


async def jwt_response(
    user: User, request: Request, response: Response, **kwargs
) -> JWTResponse:
    if user is None:
        raise BaseHTTPException(401, "unauthorized")
    origin = kwargs.get("origin", request.url.hostname)
    website = await Website.get_by_origin(origin)
    if website is None:
        raise BaseHTTPException(404, "bad_origin")

    if user.current_session:
        kwargs["jti"] = user.current_session.jti
    access_token = (
        await get_token(user, website, JWTMode.ACCESS, **kwargs)
        if user.is_active
        else ""
    )

    refresh_token = None
    refresh = kwargs.get("refresh", False)
    if refresh:
        refresh_token = await get_token(user, website, JWTMode.REFRESH, **kwargs)
        payload = jwt.decode(
            refresh_token,
            algorithms="RS256",
            options={
                "verify_signature": False,
            },
        )
        ip = request.headers.get("X-Forwarded-For", request.client.host)
        user.login_sessions.append(
            LoginSession(
                jti=payload["jti"],
                auth_method=user.current_authenticator.auth_method,
                ip=ip,
                user_agent=request.headers.get("user-agent", ""),
                location=(await get_location(ip)).get("location"),
            )
        )
        await user.save()

    if await answer_jwt_in_cookie(request):
        parent_domain = website.origin[website.origin.find(".") :]
        response.set_cookie(
            key="usso_access_token",
            value=access_token,
            httponly=True,
            max_age=website.config.access_timeout,
            domain=parent_domain,
            samesite="lax",
            # samesite="none",
            secure=True,
        )
        response.set_cookie(
            key="usso_access_available",
            value="true",
            # httponly=True,
            max_age=website.config.access_timeout,
            domain=parent_domain,
            samesite="lax",
            # samesite="none",
            secure=True,
        )
        if refresh:
            response.set_cookie(
                key="usso_user_id",
                value=user.uid[2:],
                max_age=website.config.refresh_timeout,
                domain=parent_domain,
                samesite="lax",
                # samesite="none",
                secure=True,
            )
            response.set_cookie(
                key="usso_refresh_token",
                value=refresh_token,
                httponly=True,
                max_age=website.config.refresh_timeout,
                # samesite="lax",
                samesite="none",
                secure=True,
            )
            response.set_cookie(
                key="usso_refresh_available",
                value="true",
                # httponly=True,
                max_age=website.config.refresh_timeout,
                domain=parent_domain,
                # samesite="lax",
                samesite="none",
                secure=True,
            )

    return JWTResponse(
        **{
            "access_token": access_token,
            "refresh_token": refresh_token,
        }
    )


def get_email_secret_data_from_token(token: str) -> tuple[str, str]:
    """Return the user associated with a token value."""
    try:
        origin, email, secret = base64.b64decode(token).decode("utf-8").split(":")
        return origin, email, secret
    except ValueError:
        raise BaseHTTPException(status_code=HTTP_401_UNAUTHORIZED, error="unauthorized")


async def user_data_from_token(token: str, origin: str) -> UserData | None:
    """Return the user associated with a token value."""
    website = await Website.get_by_origin(origin)

    public_key = website.get_public_key()
    try:
        decoded = jwt.decode(token, public_key, algorithms="RS256")
    except jwt.exceptions.InvalidSignatureError:
        raise BaseHTTPException(
            status_code=HTTP_401_UNAUTHORIZED, error="invalid_signature"
        )

    return UserData(**decoded)


async def user_from_token(token: str, origin: str) -> User | None:
    # Assuming 'decoded' contains user information,
    # retrieve the user and return
    user_data = await user_data_from_token(token, origin)

    if user_data.user_id is not None:
        return await User.get_by_uid(user_data.user_id)

    raise BaseHTTPException(status_code=HTTP_401_UNAUTHORIZED, error="unauthorized")


async def user_from_refresh_token(token: str, origin: str, **kwargs) -> User | None:
    # Assuming 'decoded' contains user information,
    # retrieve the user and return
    user_data = await user_data_from_token(token, origin)

    if user_data.user_id is not None:
        user = await User.get_by_uid(
            user_data.user_id
        )  # Replace with your method to get a user by ID

        if user:
            for login_session in user.login_sessions:
                if login_session.jti == user_data.jti:
                    user.current_session = login_session
                    return user

    if kwargs.get("raise_exception", True):
        raise BaseHTTPException(status_code=HTTP_401_UNAUTHORIZED, error="unauthorized")

    return None


def get_authorization_scheme_param(
    authorization_header_value: Optional[str],
) -> Tuple[str, str]:
    if not authorization_header_value:
        return "", ""
    scheme, _, param = authorization_header_value.partition(" ")
    return scheme, param


def token_from_request(request: Request) -> str:
    authorization = request.headers.get("Authorization")
    if authorization:
        scheme, _, credentials = get_authorization_scheme_param(authorization)
        if scheme.lower() == "bearer":
            return credentials

    access = request.cookies.get("usso_access_token")
    refresh = request.cookies.get("usso_refresh_token")

    if refresh:
        return refresh

    if access:
        return access

    raise BaseHTTPException(status_code=HTTP_401_UNAUTHORIZED, error="unauthorized")


async def jwt_access_security(request: Request) -> UserData | None:
    """Return the user associated with a token value."""
    origin = request.url.hostname

    authorization = request.headers.get("Authorization")
    if authorization:
        scheme, _, credentials = get_authorization_scheme_param(authorization)
        if scheme.lower() == "bearer":
            token = credentials
            return await user_data_from_token(token, origin)

    cookie_token = request.cookies.get("usso_access_token")
    if cookie_token:
        return await user_data_from_token(cookie_token, origin)

    raise BaseHTTPException(status_code=HTTP_401_UNAUTHORIZED, error="unauthorized")


async def jwt_access_security_user(request: Request) -> User | None:
    """Return the user associated with a token value."""
    origin = request.url.hostname

    authorization = request.headers.get("Authorization")
    if authorization:
        scheme, _, credentials = get_authorization_scheme_param(authorization)
        if scheme.lower() == "bearer":
            token = credentials
            return await user_from_token(token, origin)

    cookie_token = request.cookies.get("usso_access_token")
    if cookie_token:
        return await user_from_token(cookie_token, origin)

    raise BaseHTTPException(status_code=HTTP_401_UNAUTHORIZED, error="unauthorized")


async def jwt_access_security_user_None(request: Request) -> User | None:
    try:
        return await jwt_access_security_user(request)
    except BaseHTTPException:
        return None


async def jwt_refresh_security(
    request: Request, refresh_token: JWTRefresh = None, raise_exception=True
) -> User | None:
    """Return the user associated with a token value."""
    origin = request.url.hostname

    if refresh_token and refresh_token.refresh_token:
        return await user_from_refresh_token(refresh_token.refresh_token, origin)

    try:
        data = await request.json()
    except ValueError:
        data = {}

    if data and "refresh_token" in data:
        return await user_from_refresh_token(data["refresh_token"], origin)

    refresh = request.cookies.get("usso_refresh_token")
    if refresh:
        return await user_from_refresh_token(
            refresh, origin, raise_exception=raise_exception
        )

    if raise_exception:
        raise BaseHTTPException(status_code=HTTP_401_UNAUTHORIZED, error="unauthorized")
    return None


async def jwt_refresh_security_None(
    request: Request, refresh_token: JWTRefresh = None
) -> User | None:
    try:
        return await jwt_refresh_security(request, refresh_token, raise_exception=False)
    except BaseHTTPException:
        return None
