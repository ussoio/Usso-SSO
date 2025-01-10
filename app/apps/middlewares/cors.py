import fastapi
from apps.models.website import Website
from fastapi.responses import PlainTextResponse
from starlette.middleware.base import BaseHTTPMiddleware

origins = {"http://localhost", "http://localhost:3000"}


class DynamicCORSMiddleware(BaseHTTPMiddleware):
    async def get_allowed_origins(self, origins=origins, **kwargs):
        websites = await Website.list().skip(0).limit(100).to_list()
        if kwargs.get("origin"):
            origins.add(kwargs["origin"])
            return origins
        return origins | {f"https://{website.origin}" for website in websites}

    async def dispatch(self, request: fastapi.Request, call_next):
        response: fastapi.Response = await call_next(request)

        request.headers.get("access-control-request-headers")

        origin = request.headers.get("origin")
        allowed_origins = await self.get_allowed_origins(origin=origin)
        # logging.info(f"{allowed_origins}")

        # Dynamically check if the origin is allowed
        headers = {}
        if origin in allowed_origins:
            headers["Access-Control-Allow-Origin"] = origin
            headers["Access-Control-Allow-Credentials"] = "true"
            headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
            # headers["Access-Control-Allow-Headers"] = "Content-Type, *"
            headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, *"

        if request.method == "OPTIONS":
            return PlainTextResponse("OK", status_code=200, headers=headers)

        response.headers.update(headers)
        return response
