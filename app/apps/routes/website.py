"""Website router."""

import base64
import logging

from apps.middlewares.auth import create_basic_authenticator
from apps.middlewares.jwt_auth import (
    jwt_access_security_user,
    jwt_access_security_user_None,
)
from apps.models.user import BasicAuthenticator, User
from apps.models.website import Website, WebsiteConfig
from apps.serializers.website import JWKS, RSAJWK
from apps.serializers.website_user import AuthenticatorDTO
from fastapi import APIRouter, Depends, Request, Response
from fastapi_mongo_base.core.exceptions import BaseHTTPException
from fastapi_mongo_base.utils import basic
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


@router.get("/public-key.pem")
async def get_public_key(request: Request, origin: str | None = None):
    if origin is None:
        origin = request.url.hostname
    website = await Website.get_by_origin(origin)
    if website is None:
        raise BaseHTTPException(404, "website_not_found")

    public_key = website.get_public_key_pem()

    return public_key


@router.get(
    "/", include_in_schema=lambda request: request.url.hostname.endswith("usso.io")
)
async def domain_list(request: Request, user: User = Depends(jwt_access_security_user)):
    if not request.url.hostname.endswith("usso.io"):
        raise BaseHTTPException(404, "not_found", "Not found")

    websites = await Website.find({"user_uid": user.uid}).to_list()
    return websites


@router.get("/config")
async def get_config(request: Request, language: str = "fa"):
    from apps.schemas.config import get_config_model

    website = await Website.get_by_origin(request.url.hostname)
    config_model = get_config_model(website.config, language)
    return config_model


@router.get("/conf")
async def get_conf(request: Request):
    website = await Website.get_by_origin(request.url.hostname)
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
        logging.info(
            f"otp_not_found {phone} {request.url.hostname} {redis_key_query} {redis_results}"
        )
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
        logging.warning(f"user_not_found {uid} {website.origin}")
        raise BaseHTTPException(404, "user_not_found")
    for auth in user.authenticators:
        if auth.interface == website.origin:
            return user

    logging.warning(f"user_not_found {uid} {user.authenticators} {website.origin}")
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


@router.get("/users/{uid}/token")
@basic.try_except_wrapper
async def get_link_token(request: Request, uid: str):
    import uuid

    from apps.models.base import AuthMethod
    from apps.models.user import UserAuthenticator

    website = await get_website(request)
    user = await get_user(request, uid)

    auth = user.authenticators[0]
    token = base64.b64encode(
        f"{website.origin}:{auth.representor}:{uuid.uuid4()}".encode("utf-8")
    )

    temp_ua = UserAuthenticator(
        interface=website.origin,
        auth_method=AuthMethod.email_link,
        representor=auth.representor,
        secret=token,
        hash=False,
        max_age_minutes=AuthMethod.email_link.max_age_minutes,
    )
    await user.add_authenticator(temp_ua, ignore_validation=True)
    return {"token": token}


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


@router.post("/users/{uid}/authenticators")
async def set_authenticators(
    request: Request,
    uid: str,
    authenticator: BasicAuthenticator = Depends(create_basic_authenticator),
):
    user = await get_user(request, uid)
    await user.add_authenticator(authenticator, ignore_validation=True)
    return user.authenticators
