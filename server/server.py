from contextlib import asynccontextmanager

from fastapi import FastAPI
from beanie import init_beanie
from motor.motor_asyncio import AsyncIOMotorClient
from starlette.middleware.cors import CORSMiddleware

from . import db, middleware, config, redis

with open("DESCRIPTION.md", "r") as f:
    DESCRIPTION = f.read()


@asynccontextmanager
async def lifespan(app: FastAPI):  # type: ignore
    """Initialize application services."""
    await db.init_db()
    redis.init_redis()
    print("Startup complete")
    yield
    print("Shutdown complete")


app = FastAPI(
    title="Universal SSO",
    description=DESCRIPTION,
    version="0.1.0",
    contact={
        "name": "Mahdi Kiani",
        "url": "https://aision.io",
        "email": "mahdi@aision.io",
    },
    license_info={
        "name": "APACHE 2.0",
        "url": "https://github.com/mahdikiani/Universal-SSO/blob/main/LICENSE",
    },
    lifespan=lifespan,
)


app.add_middleware(middleware.DynamicCORSMiddleware)
