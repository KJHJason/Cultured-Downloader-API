# import third-party libraries
from pydantic import BaseModel

class Index(BaseModel):
    message: str
    latest_version: str

class Teapot(BaseModel):
    code: str

class PublicKeyResponse(BaseModel):
    public_key: str

class CookieJsonPayload(BaseModel):
    cookie: str
    public_key: str

class CookieJsonResponse(BaseModel):
    cookie: str

class GDriveJsonPayload(BaseModel):
    drive_id: str
    attachment_type: str

class GDriveJsonResponse(BaseModel):
    directory: list | None = None
    file: dict | None = None