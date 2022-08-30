# import Python's standard libraries
import re
from dataclasses import dataclass, field

@dataclass(frozen=True, repr=False)
class AppConstants:
    """This dataclass is used to store all the constants used in the application."""
    # API constants
    DEBUG_MODE: bool = True # TODO: Change this to False when deploying to production
    FAVICON_URL: str = "/favicon.ico"
    API_RESPONSES: dict = field(
        default_factory=lambda: {
            404: {"404": "Not found"},
            418: {"418": "I'm a teapot"},
            429: {"429": "Too many requests"}
        }
    )

    # For API documentations
    # https://fastapi.tiangolo.com/advanced/extending-openapi/
    LATEST_VER: str = "v1"
    VER_ONE: str = "v1"
    DOCS_URL: str = "/docs"
    REDOC_URL: str = "/redoc"
    OPENAPI_JSON_URL: str = "/openapi.json"
    VER_ONE_OPENAPI_JSON_URL: str = f"/{VER_ONE}{OPENAPI_JSON_URL}"

    # For encrypting/decrypting the saved user's cookie data
    RSA_KEY_ID: str = "rsa-4096-key"
    RSA_VERSION_SECRET_ID: str = "rsa-4096-key-ver"
    COOKIE_ENCRYPTION_KEY: str = "cookie-aes-key"

    # For the Google Drive API
    DRIVE_REQ_HEADERS: dict[str, str] = field(
        default_factory=lambda : {
            "User-Agent": 
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36",
            "referer": 
                "https://api.cultureddownloader.com/drive/query"
        }
    )

    # For caching
    BLUEPRINT_ENDPOINT_REGEX: re.Pattern[str] = re.compile(r"^[\w]+(.)[\w]+$")

    # For limiter configurations
    DEFAULT_REQUEST_LIMIT: str = "15 per second"
    API_REQUEST_LIMIT: str = "10 per second"

APP_CONSTANTS = AppConstants()

__all__ = [
    "APP_CONSTANTS"
]