from apps.middlewares.jwt_auth import jwt_access_security_user
from apps.models.user import User
from core.exceptions import BaseHTTPException
from fastapi import APIRouter, Body, Depends, status

from .schemas import APIKeyCreateResponseSchema, APIKeySchema, APIKeyVerifySchema
from .services import add_api_key, get_user_by_api_key, remove_api_key

router = APIRouter(prefix="/api_key", tags=["API Key"])


@router.get("/", response_model=list[APIKeySchema])
async def get_api_keys(
    user: User = Depends(jwt_access_security_user),
) -> list[APIKeySchema]:
    """
    Get all API keys.
    """

    return user.api_keys.values()


@router.post("/", response_model=APIKeyCreateResponseSchema)
async def create_api_key(
    user: User = Depends(jwt_access_security_user),
) -> APIKeyCreateResponseSchema:
    """
    Create an API key.
    """

    return await add_api_key(user)


@router.post("/verify", response_model=APIKeyVerifySchema)
async def verify_api_key(api_key: str = Body(embed=True)) -> APIKeyVerifySchema:
    """
    Verify an API key.
    """
    user, key = await get_user_by_api_key(api_key)
    if not user:
        raise BaseHTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            error="invalid_api_key",
            message="Invalid API key",
        )

    return APIKeyVerifySchema(user_id=user.uid[2:], **key.model_dump())


@router.delete("/{postfix:str}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_api_key(
    postfix: str,
    user: User = Depends(jwt_access_security_user),
) -> APIKeyCreateResponseSchema:
    """
    Create an API key.
    """

    return await remove_api_key(user, postfix)
