# import third-party libraries
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware

# import Google Cloud Logging API (third-party library)
from google.cloud import logging as gcp_logging

# import Python's standard libraries
import logging

# import local python libraries
from classes import APP_CONSTANTS, CLOUD_LOGGER, PrettyJSONResponse, \
                    CacheControlMiddleware, CacheControlURLRule, APIBadRequest
from routers import api_v1, general

"""--------------------------- Start of API Configuration ---------------------------"""

app = FastAPI(
    debug=APP_CONSTANTS.DEBUG_MODE,
    title="Cultured Downloader API",
    version=APP_CONSTANTS.LATEST_VER,
    docs_url="/latest/docs",
    redoc_url="/latest/redoc",
    openapi_url="/latest/openapi.json",
    responses={
        404: {"404": "Not found"},
        418: {"418": "I'm a teapot"}
    }
)

# Sets some global variables for the API
# accessible through request.app.config["VARIABLE_NAME"]
app.config = {
    "APP_CONSTANTS": APP_CONSTANTS,
    "CLOUD_LOGGER": CLOUD_LOGGER,
}

# Redirects all HTTP requests to HTTPS requests
# if the API is running on a production server
if (not APP_CONSTANTS.DEBUG_MODE):
    app.add_middleware(HTTPSRedirectMiddleware)

# Add cache headers to the specified routes
TEN_MINS_CACHE = "public, max-age=600"
ONE_YEAR_CACHE = "public, max-age=31536000"
app.add_middleware(
    CacheControlMiddleware, 
    routes=(
        CacheControlURLRule(path="/", cacheControl=TEN_MINS_CACHE),
        CacheControlURLRule(path="/favicon.ico", cacheControl=ONE_YEAR_CACHE),
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

app.include_router(general)
app.include_router(api_v1)  # For adding several APIs on top of the latest ver...
                            # https://fastapi.tiangolo.com/advanced/sub-applications/
                            # https://github.com/tiangolo/fastapi/issues/2806

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