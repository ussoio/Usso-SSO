from apps.api_key.routes import router as api_key_router
from apps.middlewares import cors
from apps.routes import app_auth, auth, user, website
from fastapi.staticfiles import StaticFiles
from fastapi_mongo_base.core import app_factory
from server import config

app = app_factory.create_app(
    settings=config.Settings(),
    ufaas_handler=False,  # lifespan_func=lifespan
)


app.add_middleware(cors.DynamicCORSMiddleware)


app.include_router(auth.router)
app.include_router(user.router)
app.include_router(api_key_router)
app.include_router(website.router)
app.include_router(app_auth.router)

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
