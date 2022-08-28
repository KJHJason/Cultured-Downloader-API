# import third-party libraries
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.middleware.base import RequestResponseEndpoint

# import Google Cloud Logging API (third-party library)
from google.cloud import logging as gcp_logging

# import Python's standard libraries
import logging

# import local python libraries
from classes import APP_CONSTANTS, CLOUD_LOGGER, CONSTANTS
from functions import CacheControlMiddleware, CacheControlURLRule
from routers import api_v1

"""--------------------------- Start of API Configuration ---------------------------"""

app = FastAPI(debug=APP_CONSTANTS.DEBUG_MODE)

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
        CacheControlURLRule(path="/v1/public-key", cacheControl=TEN_MINS_CACHE), 
        CacheControlURLRule(path="/", cacheControl=TEN_MINS_CACHE),
        CacheControlURLRule(path="/favicon.ico", cacheControl=ONE_YEAR_CACHE),
    )
)

# Integrate Google CLoud Logging to the API
gcp_logging.handlers.setup_logging(CLOUD_LOGGER.GOOGLE_LOGGING_HANDLER)
logging.getLogger().setLevel(logging.INFO)
@app.middleware("http")
async def log_request(request: Request, call_next: RequestResponseEndpoint):
    logging.info(f"{request.method} {request.url.path}")
    return await call_next(request)

"""--------------------------- End of API Configuration ---------------------------"""

"""--------------------------- Start of API Routes ---------------------------"""

app.include_router(api_v1)
@app.get("/")
async def index():
    return {
        "message": "Welcome to Cultured Downloader API!",
        "latest_version": "v1"
    }

@app.get("/favicon.ico")
async def favicon():
    return FileResponse(CONSTANTS.ROOT_DIR_PATH.joinpath("static", "favicon.ico"))

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