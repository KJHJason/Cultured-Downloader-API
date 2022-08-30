# import third-party libraries
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html

# import local python libraries
from functions import get_user_ip
from classes import USER_COOKIE, GoogleDrive, APIBadRequest, PrettyJSONResponse, APP_CONSTANTS, CLOUD_LOGGER
from classes.v1 import  CookieJsonPayload, GDriveJsonPayload, \
                        CookieJsonResponse, GDriveJsonResponse, PublicKeyResponse, PublicKeyAlgorithm
from classes.exceptions import CRC32ChecksumError, DecryptionError

api = FastAPI(
    debug=APP_CONSTANTS.DEBUG_MODE,
    title="Cultured Downloader API",
    version=APP_CONSTANTS.VER_ONE,
    docs_url=None,
    redoc_url=None,
    openapi_url=APP_CONSTANTS.OPENAPI_JSON_URL,
    swagger_ui_oauth2_redirect_url=None,
    responses=APP_CONSTANTS.API_RESPONSES
)

@api.get(
    path=APP_CONSTANTS.DOCS_URL,
    response_class=HTMLResponse,
    include_in_schema=False
)
async def swagger_ui_html():
    return get_swagger_ui_html(
        openapi_url=APP_CONSTANTS.VER_ONE_OPENAPI_JSON_URL,
        title=f"{api.title} - Swagger UI",
        oauth2_redirect_url=None,
        init_oauth=api.swagger_ui_init_oauth,
        swagger_favicon_url=APP_CONSTANTS.FAVICON_URL,
        swagger_ui_parameters=api.swagger_ui_parameters,
    )

@api.get(
    path=APP_CONSTANTS.REDOC_URL,
    response_class=HTMLResponse,
    include_in_schema=False
)
async def redoc_html():
    return get_redoc_html(
        openapi_url=APP_CONSTANTS.VER_ONE_OPENAPI_JSON_URL,
        title=f"{api.title} - ReDoc",
        redoc_favicon_url=APP_CONSTANTS.FAVICON_URL
    )

@api.post(
    path="/drive/query",
    description="Query Google Drive API to get the file details or all the files in a folder. Note that files or folders that has a resource key will not work and will return an empty JSON response.",
    response_model=GDriveJsonResponse,
    response_class=PrettyJSONResponse,
    include_in_schema=True
)
async def google_drive_query(request: Request, dataPayload: GDriveJsonPayload):
    queryID = dataPayload.drive_id
    gdriveType = dataPayload.attachment_type

    CLOUD_LOGGER.info(
        content=f"User {get_user_ip(request)}: Queried [{gdriveType}, {queryID}]"
    )

    if (gdriveType != "file" and gdriveType != "folder"):
        raise APIBadRequest(error="invalid attachment type")

    gdrive = GoogleDrive()
    if (gdriveType == "file"):
        return await gdrive.get_file_details(queryID)
    else:
        return gdrive.get_folder_contents(queryID)

@api.get(
    path="/{algorithm}/public-key",
    description="Get the public key for secure communication when transmitting the user's data on top of HTTPS",
    response_model=PublicKeyResponse,
    response_class=PrettyJSONResponse,
    include_in_schema=True
)
async def get_public_key(request: Request, algorithm: PublicKeyAlgorithm):
    algorithm = algorithm.lower()

    CLOUD_LOGGER.info(
        content=f"User {get_user_ip(request)}: Retrieved the public key (algorithm: {algorithm})]"
    )

    # if (algorithm == "rsa"):  # commented it out since only RSA is supported and the
                                # path parameter will be validated via the PublicKeyAlgorithm class
    return {"public_key": USER_COOKIE.get_api_public_key()}

@api.post(
    path="/encrypt-cookie", 
    description="Encrypts the user's cookie with the server's symmetric key",
    response_model=CookieJsonResponse,
    response_class=PrettyJSONResponse,
    include_in_schema=True
)
async def encrypt_cookie(request: Request, jsonPayload: CookieJsonPayload):
    CLOUD_LOGGER.info(
        content={
            "message": f"User {get_user_ip(request)}: Encrypted the cookie",
            "cookie": "REDACTED",
            "public_key": jsonPayload.public_key
        }
    )

    cookiePayload = USER_COOKIE.decrypt_cookie_payload(jsonPayload.cookie)
    if ("error" in cookiePayload):
        raise APIBadRequest(error=cookiePayload)

    try:
        encryptedCookieData = USER_COOKIE.encrypt_cookie_data(
            cookieData=cookiePayload["payload"],
            userPublicKey=jsonPayload.public_key
        )
    except (CRC32ChecksumError):
        raise APIBadRequest(error="integrity checks failed.")

    return {"cookie": encryptedCookieData}

@api.post(
    path="/decrypt-cookie",
    description="Decrypts the user's cookie with the server's symmetric key",
    response_model=CookieJsonResponse,
    response_class=PrettyJSONResponse,
    include_in_schema=True
)
async def decrypt_cookie(request: Request, jsonPayload: CookieJsonPayload):
    CLOUD_LOGGER.info(
        content={
            "message": f"User {get_user_ip(request)}: Decrypted the cookie",
            "cookie": "REDACTED",
            "public_key": jsonPayload.public_key
        }
    )

    encryptedCookiePayload = USER_COOKIE.decrypt_cookie_payload(jsonPayload.cookie)
    if ("error" in encryptedCookiePayload):
        raise APIBadRequest(error=encryptedCookiePayload)

    try:
        decryptedCookieData = USER_COOKIE.decrypt_cookie_data(
            encryptedCookieData=encryptedCookiePayload["payload"], 
            userPublicKey=jsonPayload.public_key
        )
    except (TypeError):
        raise APIBadRequest(error="encrypted cookie must be in bytes.")
    except (CRC32ChecksumError):
        raise APIBadRequest(error="integrity checks failed, please try again.")
    except (DecryptionError):
        raise APIBadRequest(error="decryption failed.")

    return {"cookie": decryptedCookieData}