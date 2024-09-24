"""Website router."""

import base64
import logging

from fastapi import APIRouter, Depends, Request, Response

from apps.middlewares.jwt_auth import (
    jwt_access_security_user,
    jwt_access_security_user_None,
)
from apps.models.user import BasicAuthenticator, User
from apps.models.website import Website, WebsiteConfig
from apps.schemas.website import AnonConfig
from apps.serializers.website import JWKS, RSAJWK
from apps.serializers.website_user import AuthenticatorDTO
from core.exceptions import BaseHTTPException
from server.db import redis_sync as redis

from .auth import user_registration

router = APIRouter(prefix="/website", tags=["Website"])


async def get_website(request: Request):
    user: User = await jwt_access_security_user_None(request=request)  # type: ignore[no-untyped-def]

    website = await Website.get_by_origin(request.url.hostname)
    if user and user.uid == website.user_uid:
        return website

    api_key = request.headers.get("x-api-key")
    if not api_key:
        raise BaseHTTPException(403, "forbidden")

    w = await Website.find_one(Website.api_key == api_key)
    if not (w and w.uid == website.uid):
        raise BaseHTTPException(403, "forbidden")
    return website


@router.get("/jwks.json", response_model=JWKS)
async def get_jwks(request: Request, origin: str | None = None) -> JWKS:
    if origin is None:
        origin = request.url.hostname
    website = await Website.get_by_origin(origin)
    if website is None:
        raise BaseHTTPException(404, "website_not_found")

    public_key = website.get_public_key()

    # Convert the public key to JWKS format
    jwk = RSAJWK(
        kty="RSA",
        use="sig",
        alg="RS256",
        n=base64.urlsafe_b64encode(public_key.public_numbers().n.to_bytes(256, "big"))
        .decode("utf-8")
        .replace("=", ""),
        e=base64.urlsafe_b64encode(public_key.public_numbers().e.to_bytes(3, "big"))
        .decode("utf-8")
        .replace("=", ""),
        kid=website.generate_kid(),
    )
    jwks = JWKS(keys=[jwk])

    return jwks


@router.get(
    "/", include_in_schema=lambda request: request.url.hostname.endswith("usso.io")
)
async def domain_list(request: Request, user: User = Depends(jwt_access_security_user)):
    if not request.url.hostname.endswith("usso.io"):
        raise BaseHTTPException(404, "not_found", "Not found")

    websites = await Website.find({"user_uid": user.uid}).to_list()
    return websites


@router.get("/config")
async def get_config(request: Request):
    from apps.schemas.config import get_config_model

    website = await Website.get_by_origin(request.url.hostname)
    config_model = get_config_model(website.config)
    return config_model
    import json

    with open("config.json", "r") as f:
        config = json.load(f)
    return config

    user: User = await jwt_access_security_user_None(request=request)  # type: ignore[no-untyped-def]
    if not user or user.uid != website.user_uid:
        if not request.headers.get("x-api-key"):
            return AnonConfig().from_config(website.config)

        api_key = request.headers.get("x-api-key")
        w = await Website.find_one(Website.api_key == api_key)
        if not (w and w.uid == website.uid):
            return AnonConfig().from_config(website.config)

    return website.config


@router.patch("/config")
async def update_config(request: Request, config: dict):
    website = await get_website(request)
    w_config = website.config.model_dump()
    w_config.update(config)
    website.config = WebsiteConfig(**w_config)
    await website.save()
    redis.delete(f"Website:{request.url.hostname}")
    return website.config


@router.get("/otp")
async def get_otp(request: Request, phone: str | None):
    logging.info(f"otp request for {phone}")
    await get_website(request)

    redis_key_query = f"OTP:{request.url.hostname}:{phone}:*"
    redis_results = redis.keys(redis_key_query)
    if not redis_results:
        raise BaseHTTPException(404, "otp_not_found")
    # return [redis.get(key) for key in redis_results]
    return {"otp": redis_results}


@router.get("/users")
async def get_users(request: Request, skip: int = 0, limit: int = 1000):
    website = await get_website(request)

    skip = max(0, skip)
    limit = max(1, min(limit, 1000))
    users = await User.find(
        {"authenticators": {"$elemMatch": {"interface": website.origin}}}
    ).to_list()

    return users


@router.get("/users/credentials")
async def get_by_credentials(request: Request, authenticator: AuthenticatorDTO):
    website = await get_website(request)
    credential = BasicAuthenticator(
        interface=website.origin, **authenticator.model_dump()
    )
    user, _ = await User.get_user_by_auth(credential)

    if not user:
        raise BaseHTTPException(404, "user_not_found")
    return user


@router.post("/users")
async def create_by_credentials(
    request: Request, response: Response, authenticator: AuthenticatorDTO
):
    website = await get_website(request)
    credential = BasicAuthenticator(
        interface=website.origin, **authenticator.model_dump()
    )
    user = await user_registration(request, response, credential)
    user_dict = user.model_dump()
    user_dict.pop("token", None)
    return user_dict


@router.get("/users/{uid:str}")
async def get_user(request: Request, uid: str):
    website = await get_website(request)

    user = await User.find_one(User.uid == uid)
    if not user:
        raise BaseHTTPException(404, "user_not_found")
    for auth in user.authenticators:
        if auth.interface == website.origin:
            return user
    raise BaseHTTPException(404, "user_not_found")


@router.post("/users/{uid:str}/credentials")
async def create_credentials_users(
    request: Request, uid: str, authenticator: AuthenticatorDTO
):
    website = await get_website(request)
    user = await get_user(request, uid)
    if not user:
        raise BaseHTTPException(404, "user_not_found")
    credential = BasicAuthenticator(
        interface=website.origin, **authenticator.model_dump()
    )
    user, _ = await User.get_user_by_auth(credential)
    if user:
        raise BaseHTTPException(409, "credential_exists")

    await user.add_authenticator(credential)
    return user


@router.get("/users/{uid}/payload")
async def get_payload(request: Request, uid: str):
    user = await get_user(request, uid)
    return user.data


@router.patch("/users/{uid}/payload")
async def update_payload(request: Request, uid: str, payload: dict):
    user = await get_user(request, uid)
    user.data.update(payload)
    await user.save()
    return user.data


@router.put("/users/{uid}/payload")
async def set_payload(request: Request, uid: str, payload: dict):
    user = await get_user(request, uid)
    user.data = payload
    await user.save()
    return user.data


'''
# @router.get("", response_model=UserSerializer)
# async def get_user(user: User = Security(jwt_access_security_user)):  # type: ignore[no-untyped-def]
#     """Return the current user."""
#     return UserSerializer(**user.model_dump())


# @router.patch("", response_model=UserSerializer)
# async def update_user(update: UserUpdate, user: User = Security(jwt_access_security_user)):  # type: ignore[no-untyped-def]
#     """Update allowed user fields."""
#     user.username = update.username
#     await user.save()
#     return user


# @router.delete("")
# async def delete_user(
#     user: User = Security(jwt_access_security_user),
# ) -> Response:
#     """Delete current user."""
#     await user.delete()
#     return Response(status_code=204)
'''
