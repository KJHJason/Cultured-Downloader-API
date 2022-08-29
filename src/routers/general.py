# import third-party libraries
from fastapi import APIRouter
from fastapi.responses import JSONResponse, FileResponse

# import local python libraries
from classes import Index, Teapot, CONSTANTS, APP_CONSTANTS, PrettyJSONResponse

general = APIRouter()

@general.get(
    path="/", 
    response_model=Index, 
    response_class=PrettyJSONResponse
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
    status_code=418
)
async def teapot():
    return {"message": "I'm a teapot"}

@general.get(
    path="/favicon.ico",
    responses={
        200: {
            "content": {"image/x-icon": {}},
        }
    },
    response_class=FileResponse
)
async def favicon():
    return FileResponse(CONSTANTS.ICON_PATH)