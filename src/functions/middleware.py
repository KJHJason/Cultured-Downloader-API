# import third-party libraries
from fastapi import Request, Response
from starlette.types import ASGIApp
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

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