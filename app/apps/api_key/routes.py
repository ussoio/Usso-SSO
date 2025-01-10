from apps.middlewares.jwt_auth import jwt_access_security_user
from apps.models.user import User
from fastapi import APIRouter, Body, Depends, status
from fastapi_mongo_base.core.exceptions import BaseHTTPException

from .schemas import (
    APIKeyCreateResponseSchema,
    APIKeyResponseSchema,
    APIKeyVerifySchema,
)
from .services import add_api_key, get_user_by_api_key, remove_api_key

router = APIRouter(prefix="/api_key", tags=["API Key"])


@router.get("/", response_model=list[APIKeyResponseSchema])
async def get_api_keys(
    user: User = Depends(jwt_access_security_user),
) -> list[APIKeyResponseSchema]:
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

    key_data = key.model_dump()
    key_data["user_id"] = str(user.user_id)
    return APIKeyVerifySchema(**key_data, token_type="api_key")


@router.delete("/{postfix:str}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_api_key(
    postfix: str,
    user: User = Depends(jwt_access_security_user),
) -> None:
    """
    Create an API key.
    """

    try:
        await remove_api_key(user, postfix)
    except KeyError:
        raise BaseHTTPException(
            status_code=404, error="api_key_not_found", message="API key not found"
        )
    except Exception:
        raise
