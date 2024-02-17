from contextlib import asynccontextmanager

import fastapi
from app import exceptions
from app.middlewares import cors
from app.routes import auth, user, website
from beanie import init_beanie
from fastapi.responses import JSONResponse
from motor.motor_asyncio import AsyncIOMotorClient
from starlette.middleware.cors import CORSMiddleware

from . import config, db, redis

with open("DESCRIPTION.md", "r") as f:
    DESCRIPTION = f.read()


@asynccontextmanager
async def lifespan(app: fastapi.FastAPI):  # type: ignore
    """Initialize application services."""
    await db.init_db()
    redis.init_redis()
    print("Startup complete")
    yield
    print("Shutdown complete")


app = fastapi.FastAPI(
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


@app.exception_handler(exceptions.BaseHTTPException)
async def base_http_exception_handler(
    request: fastapi.Request, exc: exceptions.BaseHTTPException
):
    return JSONResponse(
        status_code=exc.status_code,
        content={"message": exc.message, "error": exc.error},
    )


app.add_middleware(cors.DynamicCORSMiddleware)

app.include_router(auth.router)
app.include_router(user.router)
app.include_router(website.router)
