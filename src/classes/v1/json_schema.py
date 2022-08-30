# import third-party libraries
from pydantic import BaseModel

class Index(BaseModel):
    """The API's index page JSON schema response."""
    message: str
    latest_version: str

class Teapot(BaseModel):
    """I'm a teapot JSON schema."""
    code: str

class PublicKeyResponse(BaseModel):
    """The response model for the public key when
    the user requests to see the server's public key."""
    public_key: str

class CookieJsonPayload(BaseModel):
    """The JSON payload schema for the user when
    sending their cookie for encryption/decryption."""
    cookie: str
    public_key: str

class CookieJsonResponse(BaseModel):
    """The response to be sent back to the user
    after encryption/decryption of their sent cookie data."""
    cookie: str

class GDriveJsonPayload(BaseModel):
    """The JSON payload schema for the user
    when querying the Google Drive API."""
    drive_id: str
    attachment_type: str

class GDriveJsonResponse(BaseModel):
    """The response to be sent back to the user after
    querying the Google Drive API."""
    directory: list | None = None
    file: dict | None = None