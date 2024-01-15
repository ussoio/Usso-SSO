import fastapi
from fastapi.responses import PlainTextResponse
from starlette.middleware.base import BaseHTTPMiddleware

origins = {"http://localhost", "http://localhost:3000"}


class DynamicCORSMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: fastapi.Request, call_next):
        response: fastapi.Response = await call_next(request)

        requested_headers = request.headers.get("access-control-request-headers")
        headers = {}
        origin = request.headers.get("origin")

        # Dynamically check if the origin is allowed
        if origin in origins:
            headers["Access-Control-Allow-Origin"] = origin
            headers["Access-Control-Allow-Credentials"] = "true"
            # Add other CORS headers as needed
            headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
            headers["Access-Control-Allow-Headers"] = "*"

        if request.method == "OPTIONS":
            if requested_headers is not None:
                headers["Access-Control-Allow-Headers"] = requested_headers
            return PlainTextResponse("OK", status_code=200, headers=headers)

        response.headers.update(headers)
        return response
