# import third-party libraries
from fastapi import FastAPI, Request

# import Google Cloud Logging API (third-party library)
from google.cloud import logging as gcp_logging

# import Python's standard libraries
import re
import logging

# import local python libraries
from classes import APP_CONSTANTS, CLOUD_LOGGER, PrettyJSONResponse, \
                    CacheControlMiddleware, CacheControlURLRule, APIBadRequest
from routers import api_v1, general

"""--------------------------- Start of API Configuration ---------------------------"""

app = FastAPI(
    debug=APP_CONSTANTS.DEBUG_MODE,
    version=APP_CONSTANTS.LATEST_VER,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    swagger_ui_oauth2_redirect_url=None,
    responses=APP_CONSTANTS.API_RESPONSES
)

# Add cache headers to the specified routes
ONE_YEAR_CACHE = "public, max-age=31536000"
ONE_DAY_CACHE = "public, max-age=86400"
app.add_middleware(
    CacheControlMiddleware, 
    routes=(
        CacheControlURLRule(path="/", cacheControl=ONE_DAY_CACHE),
        CacheControlURLRule(path="/favicon.ico", cacheControl=ONE_YEAR_CACHE),
        CacheControlURLRule(path=re.compile(r"^\/v1\/(rsa)\/public-key$"), cacheControl=ONE_DAY_CACHE),
        CacheControlURLRule(path=re.compile(r"^\/v\d+\/docs$"), cacheControl=ONE_DAY_CACHE),
        CacheControlURLRule(path=re.compile(r"^\/v\d+\/redoc$"), cacheControl=ONE_DAY_CACHE),
        CacheControlURLRule(path=re.compile(r"^\/v\d+\/openapi\.json$"), cacheControl=ONE_DAY_CACHE)
    )
)

# Add custom exception handlers
@app.exception_handler(APIBadRequest)
async def api_bad_request_handler(request: Request, exc: APIBadRequest):
    return PrettyJSONResponse(content=exc.error, status_code=exc.code)

# Integrate Google CLoud Logging to the API
gcp_logging.handlers.setup_logging(CLOUD_LOGGER.GOOGLE_LOGGING_HANDLER)
logging.getLogger().setLevel(logging.INFO)

"""--------------------------- End of API Configuration ---------------------------"""

"""--------------------------- Start of API Routes ---------------------------"""

# For mounting the routes to the main API
# similar to Flask's Blueprint module
app.include_router(general)

# For adding several APIs on top of the main API...
# https://fastapi.tiangolo.com/advanced/sub-applications/
# https://github.com/tiangolo/fastapi/issues/2806
app.mount(
    path="/v1", 
    app=api_v1
)

"""--------------------------- End of API Routes ---------------------------"""

if (__name__ == "__main__"):
    # from hypercorn.config import Config
    # from hypercorn.asyncio import serve
    # import asyncio

    # config = Config()
    # config.bind = ["127.0.0.1:8000"]
    # asyncio.run(serve(app, config))
    from uvicorn import run
    run("app:app", host="127.0.0.1", port=8080, reload=True)