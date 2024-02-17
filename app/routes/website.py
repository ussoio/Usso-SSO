"""User router."""

import base64

from app.exceptions import BaseHTTPException
from app.middlewares.jwt_auth import jwt_access_security_user
from app.models.website import Website
from app.serializers.jwt_auth import UserData
from app.serializers.user import UserSerializer, UserUpdate
from app.serializers.website import JWKS, RSAJWK
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
