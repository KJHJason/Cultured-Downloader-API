# import third-party libraries
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.types import ASGIApp
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

# import Python's standard libraries
import json
import re
from typing import Any

class PrettyJSONResponse(JSONResponse):
    """Returns the JSON response with proper indentations"""
    def render(self, content: Any) -> bytes:
        return json.dumps(
            obj=content,
            ensure_ascii=False,
            allow_nan=False,
            indent=4,
            separators=(", ", ": "),
        ).encode("utf-8")

class APIBadRequest(Exception):
    """Class for the APIBadRequest exception class that will
    return a JSON response with the error message when raised"""
    def __init__(self, error: str | dict, status_code: int | None = 400):
        """Constructor for the APIBadRequest exception class

        Usage Example:
        >>> raise APIBadRequest({"error": "invalid request"})
        >>> raise APIBadRequest("invalid request") # the error message will be the same as above

        Attributes:
            error (str | dict):
                The error message to be returned to the user.
                If the error message is a str, it will be converted to a dict with the key "error".
            status_code (int | None):
                The status code to be returned to the user. (Default: 400)
        """
        self.error = error if (isinstance(error, dict)) \
                           else {"error": error}
        self.status_code = status_code

def add_exception_handlers(app: ASGIApp):
    """Adds custom exception handlers to the API"""
    @app.exception_handler(APIBadRequest)
    async def api_bad_request_handler(request: Request, exc: APIBadRequest):
        return PrettyJSONResponse(content=exc.error, status_code=exc.status_code)

class CacheControlURLRule:
    """Creates an object that contains the path and cache control headers for a route"""
    def __init__(self, path: str, cache_control: str) -> None:
        """Configure the cache control headers for a particular route URL

        Attributes:
            path (str|re.Pattern): 
                The url path of the route
            cache_control (str): 
                The cache control headers for the route
        """
        self.__path = path
        self.__cache_control = cache_control

    @property
    def path(self) -> str | re.Pattern:
        """The url path of the route"""
        return self.__path

    @property
    def cache_control(self) -> str:
        """The cache control headers for the route"""
        return self.__cache_control

class CacheControlMiddleware(BaseHTTPMiddleware):
    """Adds a Cache-Control header to the specified API routes.
    With reference to: https://github.com/attakei/fastapi-simple-cache_control"""
    def __init__(self, app: ASGIApp, routes: tuple[CacheControlURLRule] | list[CacheControlURLRule]) -> None:
        """Adds a Cache-Control header to the specified API routes.

        Attributes:
            cache_control (str):
                The cache-control header value
            routes (tuple | list):
                The API routes to add the cache-control header to
        """
        routes_rule = []
        for route in routes:
            if (isinstance(route, CacheControlURLRule)):
                routes_rule.append(route)
            else:
                raise TypeError(f"Invalid route type: {type(route)}")

        self.__routes = tuple(routes_rule)
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        user_req_path = request.url.path
        for route in self.__routes:
            if (
                (isinstance(route.path, str) and user_req_path == route.path) ^ 
                (isinstance(route.path, re.Pattern) and route.path.match(user_req_path) is not None)
            ):
                response.headers["Cache-Control"] = route.cache_control
                break
        else:
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        return response