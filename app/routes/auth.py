"""Registration router."""

from datetime import datetime, timedelta
from functools import partial

from fastapi import APIRouter, Body, Depends, Request, Response, Security
from starlette.status import HTTP_201_CREATED

from app.exceptions import BaseHTTPException
from app.middlewares.auth import create_basic_authenticator
from app.middlewares.jwt_auth import (
    get_email_secret_data_from_token,
    jwt_response,
    jwt_refresh_security,
    jwt_access_security_user,
)
from app.models.base import AuthMethod
from app.models.user import BasicAuthenticator, User, UserAuthenticator
from app.serializers.auth import BaseAuth, ForgetPasswordData
from app.serializers.jwt_auth import AccessToken, JWTResponse
from app.serializers.user import UserSerializer

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
    await user.add_authenticator(b_auth)
    return UserSerializer(**user.model_dump())


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
            raise BaseHTTPException(400, "already_exists")
        raise BaseHTTPException(400, "not_active")

    response.status_code = HTTP_201_CREATED
    token = await jwt_response(user, request, response, refresh=True)
    return UserSerializer(token=token, **user.model_dump())


@router.post("/login")
async def login(
    request: Request,
    response: Response,
    b_auth: BasicAuthenticator = Depends(create_basic_authenticator),
) -> UserSerializer:  # type: ignore[no-untyped-def]
    """Authenticate and returns the user's JWT."""
    user = await User.login(b_auth)
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


@router.post("/forgot-password")
async def forgot_password(user_auth: ForgetPasswordData, request: Request) -> Response:
    """Send password reset email."""

    b_auth = create_basic_authenticator(request, BaseAuth(representor=user_auth.email))
    user, auth = await User.get_user_by_auth(b_auth)
    if user is None:
        raise BaseHTTPException(404, "no_user")

    # todo: send reset password link to user email
    # token = access_security.create_access_token(user.jwt_subject)
    # await send_password_reset_email(email, token)
    return Response(status_code=200)


@router.post("/reset-password/{token}", response_model=UserSerializer)
async def reset_password(request: Request, token: str, password: str = embed):  # type: ignore[no-untyped-def]
    """Reset user password from token value."""
    token_email, token_secret = get_email_secret_data_from_token(token)
    b_auth = create_basic_authenticator(
        request,
        BaseAuth(
            auth_method=AuthMethod.email_link,
            representor=token_email,
            secret=token_secret,
        ),
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
            auth.interface == b_auth.origin
            and auth.auth_method == AuthMethod.email
            and auth.representor == token_email
        ):
            user.authenticators.remove(auth)

    auth = UserAuthenticator(
        interface=b_auth.origin,
        representor=token_email,
        secret=password,
        validated_at=datetime.utcnow(),
    )

    user.is_active = True
    await user.add_authenticator(auth)

    return user


@router.get("/validate/{token:path}", response_model=UserSerializer)
async def validate(request: Request, token: str):  # type: ignore[no-untyped-def]
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

    return user
