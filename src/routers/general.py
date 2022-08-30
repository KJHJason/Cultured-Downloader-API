# import third-party libraries
from fastapi import APIRouter
from fastapi.responses import FileResponse, RedirectResponse

# import local python libraries
from classes.v1 import Index, Teapot
from classes import CONSTANTS, APP_CONSTANTS, PrettyJSONResponse

general = APIRouter()

@general.get(
    path="/", 
    response_model=Index, 
    response_class=PrettyJSONResponse,
    include_in_schema=False
)
async def index():
    return {
        "message": "Welcome to Cultured Downloader API!",
        "latest_version": APP_CONSTANTS.LATEST_VER
    }

@general.get(
    path="/418", 
    response_model=Teapot, 
    response_class=PrettyJSONResponse, 
    status_code=418,
    include_in_schema=False
)
async def teapot():
    return {"message": "I'm a teapot"}

@general.get(
    path=APP_CONSTANTS.FAVICON_URL,
    responses={
        200: {
            "content": {"image/x-icon": {}},
        }
    },
    response_class=FileResponse,
    include_in_schema=False
)
async def favicon():
    return FileResponse(CONSTANTS.ICON_PATH)

@general.get(
    path="/latest/docs",
    response_class=RedirectResponse,
    include_in_schema=False
)
async def latest_docs():
    return RedirectResponse(url=f"/{APP_CONSTANTS.LATEST_VER}{APP_CONSTANTS.DOCS_URL}")

@general.get(
    path="/latest/redoc",
    response_class=RedirectResponse,
    include_in_schema=False
)
async def latest_redocs():
    return RedirectResponse(url=f"/{APP_CONSTANTS.LATEST_VER}{APP_CONSTANTS.REDOC_URL}")

@general.get(
    path="/latest/openapi.json",
    response_class=RedirectResponse,
    include_in_schema=False
)
async def latest_openapi_json():
    return RedirectResponse(url=f"/{APP_CONSTANTS.LATEST_VER}{APP_CONSTANTS.OPENAPI_JSON_URL}")