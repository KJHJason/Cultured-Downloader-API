# import third-party libraries
from pydantic import BaseModel

class CookieJsonPayload(BaseModel):
    cookie: str
    public_key: str

class GDriveJsonPayload(BaseModel):
    drive_id: str
    attachment_type: str