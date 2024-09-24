"""Registration router."""

import hashlib
import hmac
import uuid
from datetime import datetime

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, field_validator

from apps.middlewares.jwt_auth import jwt_response
from apps.models.base import AuthMethod
from apps.models.user import BasicAuthenticator, User
from apps.serializers.jwt_auth import AccessToken
from core.exceptions import BaseHTTPException

from .website import get_website

router = APIRouter(prefix="/app-auth", tags=["extensions"])


@router.post("/register")
async def app_registration(request: Request, response: Response):
    """Create a new app."""
    # check access app registration?!
    # work with x-api-key
    website = await get_website(request)

    # create app credentials
    app_id = f"{uuid.uuid4()}"
    app_secret = hashlib.sha256(
        f"{app_id}{datetime.now().timestamp()}{uuid.uuid4()}".encode()
    ).hexdigest()

    b_auth = BasicAuthenticator(
        interface=website.origin,
        auth_method=AuthMethod.app,
        representor=app_id,
        secret=app_secret,
    )
    _, success = await User.register(b_auth)
    if not success:
        raise BaseHTTPException(400, "App registration failed.")

    # return app credentials
    return {"app_id": app_id, "app_secret": app_secret}


# extension get access_token {app_id, hash(app_secret, timestamp), timestamp, business_name} -->
class AppAuth(BaseModel):
    # app_secret: str
    app_id: str
    scopes: list[str]
    timestamp: int
    sso_url: str
    secret: str

    @field_validator("timestamp")
    def check_timestamp(cls, v: int):
        if type(v) != int:
            v = int(v)

        if datetime.now().timestamp() - v > 60:
            raise ValueError("Timestamp expired.")

        return v

    @property
    def hash_key_part(self):
        scopes_hash = hashlib.sha256("".join(self.scopes).encode()).hexdigest()
        return f"{self.app_id}{scopes_hash}{self.timestamp}{self.sso_url}"

    def check_secret(self, app_secret: bytes | str):
        if type(app_secret) != str:
            app_secret = app_secret.decode("utf-8")

        key = f"{self.hash_key_part}{app_secret}"
        return hmac.compare_digest(
            self.secret, hashlib.sha256(key.encode()).hexdigest()
        )

    def get_secret(self, app_secret: bytes | str):
        if type(app_secret) != str:
            app_secret = app_secret.decode("utf-8")

        key = f"{self.hash_key_part}{app_secret}"
        return hashlib.sha256(key.encode()).hexdigest()


@router.post("/access", response_model=AccessToken)
async def access(
    request: Request, response: Response, app_auth: AppAuth
) -> AccessToken:
    """Authenticate and returns the user's JWT."""
    # check app credentials
    # TODO rate limit

    b_auth = BasicAuthenticator(
        # interface=app_auth.sso_url,
        interface=request.url.hostname,
        auth_method=AuthMethod.app,
        representor=app_auth.app_id,
    )
    app, auth = await User.get_user_by_auth(b_auth)
    if not app or not auth:
        raise BaseHTTPException(401, "unauthorized", "App not found.")

    if not app_auth.check_secret(auth.secret):
        raise BaseHTTPException(401, "unauthorized", "App authentication failed.")

    app.current_authenticator = auth

    # check app scopes, install
    # TODO make sure how to manage the user_id, app_id, token_type, ...
    # TODO PKI Signature ?
    # TODO
    # TODO check if app_auth.sso_url is in the list of websites that the api-os has access to

    # create access token
    token = await jwt_response(
        app,
        request,
        response,
        refresh=False,
        scopes=app_auth.scopes,
        app_id=auth.representor,
        origin=app_auth.sso_url,
    )
    return AccessToken(**token.model_dump())
