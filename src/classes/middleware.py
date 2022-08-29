# import third-party libraries
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.types import ASGIApp
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

# import Python's standard libraries
import json
from typing import Any

class PrettyJSONResponse(JSONResponse):
    def render(self, content: Any) -> bytes:
        return json.dumps(
            obj=content,
            ensure_ascii=False,
            allow_nan=False,
            indent=4,
            separators=(",", ":"),
        ).encode("utf-8")

class APIBadRequest(Exception):
    """Class for the APIBadRequest exception class that will
    return a JSON response with the error message when raised"""
    def __init__(self, error: str | dict, statusCode: int | None = 400):
        """Constructor for the APIBadRequest exception class

        Usage Example:
        >>> raise APIBadRequest({"error": "invalid request"})
        >>> raise APIBadRequest("invalid request") # the error message will be the same as above

        Attributes:
            error (str | dict):
                The error message to be returned to the user.
                If the error message is a str, it will be converted to a dict with the key "error".
            statusCode (int | None):
                The status code to be returned to the user. (Default: 400)
        """
        self.error = error if (isinstance(error, dict)) \
                           else {"error": error}
        self.code = statusCode

class CacheControlURLRule:
    """Creates an object that contains the path and cache control headers for a route"""
    def __init__(self, path: str, cacheControl: str) -> None:
        """Configure the cache control headers for a particular route URL

        Attributes:
            path (str): 
                The url path of the route
            cacheControl (str): 
                The cache control headers for the route
        """
        self.__path = path
        self.__cacheControl = cacheControl

    @property
    def path(self) -> str:
        """The url path of the route"""
        return self.__path

    @property
    def cacheControl(self) -> str:
        """The cache control headers for the route"""
        return self.__cacheControl

class CacheControlMiddleware(BaseHTTPMiddleware):
    """Adds a Cache-Control header to the specified API routes.
    With reference to: https://github.com/attakei/fastapi-simple-cachecontrol"""
    def __init__(self, app: ASGIApp, routes: tuple[CacheControlURLRule] | list[CacheControlURLRule]) -> None:
        """Adds a Cache-Control header to the specified API routes.

        Attributes:
            cacheControl (str):
                The cache-control header value
            routes (tuple | list):
                The API routes to add the cache-control header to
        """
        routesRule = []
        for route in routes:
            if (isinstance(route, CacheControlURLRule)):
                routesRule.append(route)
            else:
                raise TypeError(f"Invalid route type: {type(route)}")

        self.__routes = tuple(routesRule)
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        userReqPath = request.url.path
        for route in self.__routes:
            if (userReqPath == route.path):
                response.headers["Cache-Control"] = route.cacheControl
                break
        else:
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        return response