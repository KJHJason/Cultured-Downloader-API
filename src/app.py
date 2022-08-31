# import third-party libraries
from fastapi import FastAPI

# import Google Cloud Logging API (third-party library)
from google.cloud import logging as gcp_logging

# import Python's standard libraries
import re
import logging

# import local python libraries
from classes import APP_CONSTANTS, CLOUD_LOGGER, \
                    CacheControlMiddleware, CacheControlURLRule, add_exception_handlers
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
# when the app is not in debug mode
if (not APP_CONSTANTS.DEBUG_MODE):
    ONE_YEAR_CACHE = "public, max-age=31536000"
    ONE_DAY_CACHE = "public, max-age=86400"
    app.add_middleware(
        CacheControlMiddleware, 
        routes=(
            CacheControlURLRule(path="/", cache_control=ONE_DAY_CACHE),
            CacheControlURLRule(path="/favicon.ico", cache_control=ONE_YEAR_CACHE),
            CacheControlURLRule(path=re.compile(r"^\/v1\/(rsa)\/public-key$"), cache_control=ONE_DAY_CACHE),
            CacheControlURLRule(path=re.compile(r"^\/v\d+\/docs$"), cache_control=ONE_DAY_CACHE),
            CacheControlURLRule(path=re.compile(r"^\/v\d+\/redoc$"), cache_control=ONE_DAY_CACHE),
            CacheControlURLRule(path=re.compile(r"^\/v\d+\/openapi\.json$"), cache_control=ONE_DAY_CACHE)
        )
    )

# Add custom exception handlers
add_exception_handlers(app=app)
add_exception_handlers(app=api_v1)

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
    from uvicorn import run
    run("app:app", host="127.0.0.1", port=8080, reload=True)