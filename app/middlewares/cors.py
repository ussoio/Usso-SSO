import fastapi
from fastapi.responses import PlainTextResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.models.website import Website

origins = {"http://localhost", "http://localhost:3000"}


class DynamicCORSMiddleware(BaseHTTPMiddleware):
    async def get_allowed_origins(self, origins=origins, **kwargs):
        websites = Website.list()
        if kwargs.get("origin"):
            origins.add(kwargs["origin"])
            return origins
        return origins | {
            f"https://{website.origin}" async for website in websites.skip(0).limit(10)
        }

    async def dispatch(self, request: fastapi.Request, call_next):
        response: fastapi.Response = await call_next(request)

        request.headers.get("access-control-request-headers")
        headers = {}
        origin = f"https://{request.url.hostname}"
        origins = await self.get_allowed_origins(origin=origin)

        # Dynamically check if the origin is allowed
        if origin in origins:
            headers["Access-Control-Allow-Origin"] = origin
            headers["Access-Control-Allow-Credentials"] = "true"
            # Add other CORS headers as needed
            headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
            headers["Access-Control-Allow-Headers"] = "*"

        if request.method == "OPTIONS":
            # if requested_headers is not None:
            #     headers["Access-Control-Allow-Headers"] = requested_headers
            return PlainTextResponse("OK", status_code=200, headers=headers)

        response.headers.update(headers)
        return response
