"""User router."""

import base64
import logging

from app.exceptions import BaseHTTPException
from app.middlewares.jwt_auth import (
    jwt_access_security_user,
    jwt_access_security_user_None,
)
from app.models.website import Website, WebsiteConfig
from app.models.user import User
from app.serializers.jwt_auth import UserData
from app.serializers.user import UserSerializer, UserUpdate
from app.serializers.website import JWKS, RSAJWK
from server.redis import redis
from fastapi import APIRouter, Depends, HTTPException, Request, Response, Security

router = APIRouter(prefix="/website", tags=["Website"])


@router.get("/jwks.json", response_model=JWKS)
async def get_jwks(request: Request) -> JWKS:
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


@router.get("/config")
async def get_config(request: Request):  # type: ignore[no-untyped-def]
    """Return the current user."""
    user: User = await jwt_access_security_user_None(request=request)  # type: ignore[no-untyped-def]
    website = await Website.get_by_origin(request.url.hostname)
    if user and user.uid == website.user_uid:
        return website.config

    if request.headers.get("x-api-key"):
        api_key = request.headers.get("x-api-key")
        w = await Website.find_one(Website.api_key == api_key)
        if w and w.uid == website.uid:
            return w.config
    raise BaseHTTPException(403, "forbidden")


@router.patch("/config")
async def get_config(request: Request, config: dict):  # type: ignore[no-untyped-def]
    """Return the current user."""
    user: User = await jwt_access_security_user_None(request=request)  # type: ignore[no-untyped-def]
    website = await Website.get_by_origin(request.url.hostname)
    if user and user.uid == website.user_uid:
        w_config = website.config.model_dump()
        w_config.update(config)
        website.config = WebsiteConfig(**w_config)
        await website.save()
        redis.delete(f"Website:{request.url.hostname}")
        return website.config

    if request.headers.get("x-api-key"):
        api_key = request.headers.get("x-api-key")
        w = await Website.find_one(Website.api_key == api_key)
        if w and w.uid == website.uid:
            w_config = website.config.model_dump()
            w_config.update(config)
            w.config = WebsiteConfig(**w_config)
            await w.save()
            redis.delete(f"Website:{request.url.hostname}")
            return w.config

    raise BaseHTTPException(403, "forbidden")


@router.get("/otp")
async def get_user(request: Request, phone: str):  # type: ignore[no-untyped-def]
    user: User = await jwt_access_security_user_None(request=request)  # type: ignore[no-untyped-def]
    website = await Website.get_by_origin(request.url.hostname)
    api_key = request.headers.get("x-api-key")
    redis_key_query = f"OTP:{request.url.hostname}:{phone}:*"
    redis_results = redis.keys(redis_key_query)
    if user and user.uid == website.user_uid:
        return {"otp": redis_results}
    if api_key:
        w = await Website.find_one(Website.api_key == api_key)
        if w and w.uid == website.uid:
            return [redis.get(key) for key in redis_results]
    raise BaseHTTPException(403, "forbidden")


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
