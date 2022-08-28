# import third-party libraries
from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse

# import local python libraries
from functions import send_request, get_user_ip
from classes import USER_COOKIE, CookieJsonPayload, GDriveJsonPayload
from classes.exceptions import CRC32ChecksumError, DecryptionError

# import Python's standard libraries
from typing import Optional

api_v1 = APIRouter(
    prefix="/v1",
    responses={404: {"description": "Not found"}}
)

@api_v1.post("/query")
async def query(request: Request, dataPayload: GDriveJsonPayload):
    queryID = dataPayload.drive_id
    gdriveType = dataPayload.attachment_type

    request.app.config["CLOUD_LOGGER"].write_log_entry(
        logMessage=f"User {get_user_ip(request)}: Queried [{gdriveType}, {queryID}]",
        severity="INFO"
    )

    if (gdriveType != "file" and gdriveType != "folder"):
        return JSONResponse(content={"error": "invalid attachment type"}, status_code=400)

    return send_request(queryID, gdriveType)

@api_v1.get("/public-key")
async def get_rsa_public_key(request: Request, algorithm: Optional[str] = Query(default="rsa", max_length=10)):
    algorithm = algorithm.lower()

    request.app.config["CLOUD_LOGGER"].write_log_entry(
        logMessage=f"User {get_user_ip(request)}: Retrieved the public key (algorithm: {algorithm})]",
        severity="INFO"
    )

    if (algorithm == "rsa"):
        return {"public_key": USER_COOKIE.get_api_public_key()}
    else:
        return JSONResponse(
            content={"error": "invalid algorithm...", "supported_algorithms": ["rsa"]}, 
            status_code=400
        )

@api_v1.post("/encrypt-cookie")
async def encrypt(request: Request, jsonPayload: CookieJsonPayload):
    request.app.config["CLOUD_LOGGER"].write_log_entry(
        logMessage={
            "message": f"User {get_user_ip(request)}: Encrypted the cookie",
            "cookie": "REDACTED",
            "public_key": jsonPayload.public_key
        },
        severity="INFO"
    )

    cookiePayload = USER_COOKIE.decrypt_cookie_payload(jsonPayload.cookie)
    if ("error" in cookiePayload):
        return JSONResponse(content=cookiePayload, status_code=400)

    try:
        encryptedCookieData = USER_COOKIE.encrypt_cookie_data(
            cookieData=cookiePayload["payload"],
            userPublicKey=jsonPayload.public_key
        )
    except (CRC32ChecksumError):
        return JSONResponse(content={"error": "integrity checks failed."}, status_code=400)

    return {"cookie": encryptedCookieData}

@api_v1.post("/decrypt-cookie")
async def decrypt(request: Request, jsonPayload: CookieJsonPayload):
    request.app.config["CLOUD_LOGGER"].write_log_entry(
        logMessage={
            "message": f"User {get_user_ip(request)}: Decrypted the cookie",
            "cookie": "REDACTED",
            "public_key": jsonPayload.public_key
        },
        severity="INFO"
    )

    encryptedCookiePayload = USER_COOKIE.decrypt_cookie_payload(jsonPayload.cookie)
    if ("error" in encryptedCookiePayload):
        return encryptedCookiePayload

    try:
        decryptedCookieData = USER_COOKIE.decrypt_cookie_data(
            encryptedCookieData=encryptedCookiePayload["payload"], 
            userPublicKey=jsonPayload.public_key
        )
    except (TypeError):
        return JSONResponse(content={"error": "encrypted cookie must be in bytes."}, status_code=400)
    except (CRC32ChecksumError):
        return JSONResponse(content={"error": "integrity checks failed, please try again."}, status_code=400)
    except (DecryptionError):
        return JSONResponse(content={"error": "decryption failed."}, status_code=400)

    return {"cookie": decryptedCookieData}