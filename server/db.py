from app.models import user, website
from beanie import init_beanie
from motor.motor_asyncio import AsyncIOMotorClient

from .config import CONFIG


async def init_db():
    db = AsyncIOMotorClient(CONFIG.mongo_uri).sso
    await init_beanie(database=db, document_models=[user.User, website.Website])
    return db
