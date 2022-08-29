# import third-party libraries
from fastapi import APIRouter, Query, Request

# import local python libraries
from functions import get_user_ip
from classes import USER_COOKIE, CookieJsonPayload, GDriveJsonPayload, PrettyJSONResponse, \
                    CookieJsonResponse, PublicKeyResponse, GoogleDrive, GDriveJsonResponse, APIBadRequest
from classes.exceptions import CRC32ChecksumError, DecryptionError

api = APIRouter(prefix="/v1")

@api.post(
    path="/drive/query",
    description="Query Google Drive API to get the file details or all the files in a folder",
    response_model=GDriveJsonResponse,
    response_class=PrettyJSONResponse
)
async def google_drive_query(request: Request, dataPayload: GDriveJsonPayload):
    queryID = dataPayload.drive_id
    gdriveType = dataPayload.attachment_type

    request.app.config["CLOUD_LOGGER"].info(
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
    path="/public-key",
    description="Get the public key for secure communication when transmitting the user's data on top of HTTPS",
    response_model=PublicKeyResponse,
    response_class=PrettyJSONResponse
)
async def get_public_key(request: Request, algorithm: str | None = Query(default="rsa", max_length=10)):
    algorithm = algorithm.lower()

    request.app.config["CLOUD_LOGGER"].info(
        content=f"User {get_user_ip(request)}: Retrieved the public key (algorithm: {algorithm})]"
    )

    if (algorithm == "rsa"):
        return {"public_key": USER_COOKIE.get_api_public_key()}
    else:
        raise APIBadRequest(
            error={"error": "invalid algorithm...", "supported_algorithms": ["rsa"]}
        )

@api.post(
    path="/encrypt-cookie", 
    description="Encrypts the user's cookie with the server's symmetric key",
    response_model=CookieJsonResponse,
    response_class=PrettyJSONResponse
)
async def encrypt_cookie(request: Request, jsonPayload: CookieJsonPayload):
    request.app.config["CLOUD_LOGGER"].info(
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
    response_class=PrettyJSONResponse
)
async def decrypt_cookie(request: Request, jsonPayload: CookieJsonPayload):
    request.app.config["CLOUD_LOGGER"].info(
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