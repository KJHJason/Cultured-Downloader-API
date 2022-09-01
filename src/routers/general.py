# import third-party libraries
from fastapi import APIRouter, Request, Response
from fastapi.responses import FileResponse, RedirectResponse, HTMLResponse

# import local python libraries
from functions import format_server_time, get_jinja2_templates, add_csp_header_to_response
from classes import CONSTANTS, APP_CONSTANTS, PrettyJSONResponse

web_app_general = APIRouter(
    include_in_schema=False
)
templates = get_jinja2_templates()

@web_app_general.get(
    path="/",
    response_class=HTMLResponse
)
async def index(request: Request, response: Response):
    server_time = {"server_time": format_server_time()}
    add_csp_header_to_response(response)
    return templates.TemplateResponse(
        name="general/home.html", 
        context={"request": request, "response": response, "context": server_time},
        headers=response.headers
    )

@web_app_general.get("/favicon.ico")
async def favicon():
    """Return the favicon of the web app."""
    return await FileResponse(CONSTANTS.ICON_PATH)

@web_app_general.get(
    path="/418",
    response_class=PrettyJSONResponse, 
    status_code=418
)
async def teapot():
    return {
        "code": 418, 
        "message": "I'm a teapot"
    }

@web_app_general.get(
    path="/latest/docs",
    response_class=RedirectResponse
)
async def latest_docs():
    return RedirectResponse(url=f"/{APP_CONSTANTS.LATEST_VER}{APP_CONSTANTS.DOCS_URL}")

@web_app_general.get(
    path="/latest/redoc",
    response_class=RedirectResponse
)
async def latest_redocs():
    return RedirectResponse(url=f"/{APP_CONSTANTS.LATEST_VER}{APP_CONSTANTS.REDOC_URL}")

@web_app_general.get(
    path="/latest/openapi.json",
    response_class=RedirectResponse
)
async def latest_openapi_json():
    return RedirectResponse(url=f"/{APP_CONSTANTS.LATEST_VER}{APP_CONSTANTS.OPENAPI_JSON_URL}")