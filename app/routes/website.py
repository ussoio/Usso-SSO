"""Website router."""

import logging
import base64

from server.redis import redis
from app.exceptions import BaseHTTPException
from app.middlewares.jwt_auth import (
    jwt_access_security_user,
    jwt_access_security_user_None,
)
from app.models.website import Website
from app.serializers.jwt_auth import UserData
from app.serializers.user import UserSerializer, UserUpdate
from app.serializers.website import JWKS, RSAJWK
from app.serializers.website_user import AuthenticatorDTO
from app.models.website import Website, WebsiteConfig
from app.models.user import User, BasicAuthenticator
from fastapi import APIRouter, Depends, HTTPException, Request, Response, Security

router = APIRouter(prefix="/website", tags=["Website"])


async def get_website(request: Request):
    user: User = await jwt_access_security_user_None(request=request)  # type: ignore[no-untyped-def]
    website = await Website.get_by_origin(request.url.hostname)
    if not user or user.uid != website.user_uid:
        if not request.headers.get("x-api-key"):
            raise BaseHTTPException(403, "forbidden")

        api_key = request.headers.get("x-api-key")
        w = await Website.find_one(Website.api_key == api_key)
        if not (w and w.uid == website.uid):
            raise BaseHTTPException(403, "forbidden")
    return website


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
async def get_config(request: Request):
    website = await get_website(request)
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
async def get_user(request: Request, phone: str|None):  # type: ignore[no-untyped-def]
    website = await get_website(request)

    redis_key_query = f"OTP:{request.url.hostname}:{phone}:*"
    redis_results = redis.keys(redis_key_query)
    if not redis_results:
        raise BaseHTTPException(404, "otp_not_found")
    # return [redis.get(key) for key in redis_results]
    return {"otp": redis_results}


@router.get("/users")
async def get_users(request: Request, skip: int = 0, limit: int = 10):
    website = await get_website(request)

    skip = max(0, skip)
    limit = max(1, min(limit, 100))
    users = (
        User.find_all(User.authenticators.interface == website.origin)
        .skip(skip)
        .limit(limit)
    )
    return [u.model_dump() async for u in users]


@router.get("/users/credentials")
async def get_users(request: Request, authenticator: AuthenticatorDTO):
    website = await get_website(request)
    credential = BasicAuthenticator(interface=website.origin, **authenticator.model_dump())
    user = await User.get_user_by_auth(credential)

    if not user:
        raise BaseHTTPException(404, "user_not_found")
    return user


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
async def get_users(request: Request, uid: str, authenticator: AuthenticatorDTO):
    website = await get_website(request)
    user = await get_user(request, uid)
    credential = BasicAuthenticator(
        interface=website.origin, **authenticator.model_dump()
    )
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
