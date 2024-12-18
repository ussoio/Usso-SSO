import json
import logging
from contextlib import asynccontextmanager

import fastapi
import pydantic
from apps.middlewares import cors
from core import exceptions
from fastapi.responses import JSONResponse
from json_advanced import dumps
from server import config, db


@asynccontextmanager
async def lifespan(app: fastapi.FastAPI):  # type: ignore
    """Initialize application services."""
    await db.init_db()
    config.Settings.config_logger()

    logging.info("Startup complete")
    yield
    logging.info("Shutdown complete")


config.Settings.config_logger()

with open("DESCRIPTION.md", "r") as f:
    DESCRIPTION = f.read()


app = fastapi.FastAPI(
    title="Universal SSO",
    description=DESCRIPTION,
    version="0.5.0",
    contact={
        "name": "Mahdi Kiani",
        "url": "https://usso.io",
        "email": "mahdi@mahdikiani.com",
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


@app.exception_handler(pydantic.ValidationError)
@app.exception_handler(fastapi.exceptions.ResponseValidationError)
async def pydantic_exception_handler(
    request: fastapi.Request, exc: pydantic.ValidationError
):
    return JSONResponse(
        status_code=500,
        content={
            "message": str(exc),
            "error": "Exception",
            "erros": json.loads(dumps(exc.errors())),
        },
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: fastapi.Request, exc: Exception):
    import traceback

    traceback_str = "".join(traceback.format_tb(exc.__traceback__))
    # body = request._body

    logging.error(f"Exception: {traceback_str} {exc}")
    logging.error(f"Exception on request: {request.url}")
    # logging.error(f"Exception on request: {await request.body()}")
    return JSONResponse(
        status_code=500,
        content={"message": str(exc), "error": "Exception"},
    )


app.add_middleware(cors.DynamicCORSMiddleware)

from apps.api_key.routes import router as api_key_router
from apps.routes import app_auth, auth, user, website

app.include_router(auth.router)
app.include_router(user.router)
app.include_router(api_key_router)
app.include_router(website.router)
app.include_router(app_auth.router)

from fastapi.staticfiles import StaticFiles

app.mount("/web", StaticFiles(directory=config.Settings.base_dir / "web"), name="web")

app.mount(
    "/_next",
    StaticFiles(directory=config.Settings.base_dir / "web" / "_next"),
    name="_next",
)

app.mount(
    "/fonts",
    StaticFiles(directory=config.Settings.base_dir / "web" / "fonts"),
    name="fonts",
)


@app.get("/")
async def index():
    return {"message": "Hello World!"}


@app.get("/health")
async def index():
    return {"status": "ok"}
