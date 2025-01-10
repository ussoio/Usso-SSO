import logging
import uuid
from datetime import datetime

import bcrypt
from usso.b64tools import b64_decode_uuid, b64_encode_uuid_strip

from apps.models.user import User
from apps.util.str_tools import generate_random_chars

from .schemas import APIKeyCreateResponseSchema, APIKeySchema


def generate_api_key(uid: uuid.UUID, length: int = 64):
    raw_key = f"uak_{b64_encode_uuid_strip(uid)}_{generate_random_chars(length)}"
    hashed_key = bcrypt.hashpw(raw_key.encode("utf-8"), bcrypt.gensalt())
    postfix = raw_key[-3:]
    pattern = f'{raw_key[:6]}{"*"*30}{postfix}'
    return raw_key, hashed_key, pattern, postfix


def generate_unique_api_key(user: User, length: int = 64):
    """Generate a unique API key with a unique postfix."""
    for i in range(100000):
        logging.info(f"Generating API key {user.user_id}, {user}")
        raw_key, hashed_key, pattern, postfix = generate_api_key(user.user_id, length)
        if postfix not in user.api_keys:
            return raw_key, hashed_key, pattern, postfix
    raise ValueError("Failed to generate a unique API key")


async def add_api_key(user: User, length: int = 64) -> APIKeyCreateResponseSchema:
    raw_key, hashed_key, pattern, postfix = generate_unique_api_key(user, length)
    key = APIKeySchema(
        user_id=user.user_id,
        hashed_key=hashed_key,
        api_key_pattern=pattern,
        postfix=postfix,
    )
    user.api_keys[postfix] = key
    await user.save()

    response = APIKeyCreateResponseSchema(api_key=raw_key, **key.model_dump())
    return response


async def get_user_by_api_key(api_key: str) -> tuple[User, APIKeySchema]:
    uid_pos = api_key.find("_")
    uid = b64_decode_uuid(api_key[uid_pos + 1 : uid_pos + 23])
    user = await User.find_one({"uid": f"u_{uid}"})
    logging.info(f"uid: {uid} {type(uid)} {user}")
    if not user:
        return None, None
    postfix = api_key[-3:]

    key = user.api_keys.get(postfix)
    if key and bcrypt.checkpw(api_key.encode("utf-8"), key.hashed_key):
        key.last_used_at = datetime.now()
        await user.save()
        return user, key

    return None, None


async def remove_api_key(user: User, postfix: str) -> APIKeyCreateResponseSchema:
    user.api_keys.pop(postfix)
    await user.save()
    return
