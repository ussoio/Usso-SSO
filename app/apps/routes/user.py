"""User router."""

from apps.middlewares.jwt_auth import jwt_access_security_user
from apps.models.user import User
from apps.serializers.user import UserSerializer, UserUpdate
from fastapi import APIRouter, Response, Security

router = APIRouter(prefix="/user", tags=["User"])


@router.get("", response_model=UserSerializer)
async def get_user(user: User = Security(jwt_access_security_user)):  # type: ignore[no-untyped-def]
    """Return the current user."""
    return UserSerializer(**user.model_dump())


@router.patch("", response_model=UserSerializer)
async def update_user(
    update: UserUpdate,
    user: User = Security(jwt_access_security_user),
):
    """Update allowed user fields."""
    user.username = update.username
    await user.save()
    return user


@router.delete("")
async def delete_user(
    user: User = Security(jwt_access_security_user),
) -> Response:
    """Delete current user."""
    await user.delete()
    return Response(status_code=204)


@router.post("/verify", response_model=UserSerializer)
async def verify_user(user: User = Security(jwt_access_security_user)):  # type: ignore[no-untyped-def]
    """Check the current user."""
    return UserSerializer(**user.model_dump())
