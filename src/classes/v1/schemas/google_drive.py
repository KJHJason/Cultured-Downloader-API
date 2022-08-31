# import third-party libraries
from pydantic import BaseModel, Field

# import Python's standard libraries
import enum

@enum.unique
class GDriveAttachmentType(str, enum.Enum):
    """Supported attachment type when quering Google Drive API."""
    FILE = "file"
    FOLDER = "folder"

class GDriveJsonRequest(BaseModel):
    """The JSON payload schema for the user
    when querying the Google Drive API."""
    drive_id: str | set[str] = Field(
        min_items=2
    )
    attachment_type: GDriveAttachmentType

# class GDriveBaseErrorResponse(BaseModel):
#     """The error details schema for Google Drive API."""
#     code: int
#     message: str

# class GDriveDetailedErrorResponse(GDriveBaseErrorResponse):
#     """The API's formatted error response schema after querying from Google Drive API."""
#     suggested_action: str | None = None

# class GDriveDefaultErrorResponse(GDriveBaseErrorResponse):
#     """Google Drive API's default error reasons response schema."""
#     errors: list[dict] | None = None

# class GDriveError(BaseModel):
#     """The JSON schema for the error message
#     when the query encountered errors such as file not found."""
#     error: GDriveBaseErrorResponse | GDriveDetailedErrorResponse | GDriveDefaultErrorResponse

# class FileFields(BaseModel):
#     """The JSON schema for the file details
#     when querying the Google Drive API."""
#     kind: str
#     id: str
#     name: str
#     mimeType: str

# class FolderMimetype(BaseModel):
#     """The JSON schema for the folder mimetype"""
#     folder: FileFields

# class FileMimetype(BaseModel):
#     """The JSON schema for the file mimetype"""
#     file: FileFields

# class FolderContents(BaseModel):
#     """The response to be sent back to the user
#     after querying Google Drive API for the folder contents."""
#     folder_id: str
#     directory: list[FolderMimetype | FileMimetype | GDriveError]

# FolderContentsResponse = 

# class FileDetails(BaseModel):
#     """The response to be sent back to the user
#     after querying Google Drive API for a file details."""
#     file: FolderMimetype | FileMimetype

# class FileErrorDetails(BaseModel):
#     """The error response to be sent back to the user
#     if the query encountered errors such as file not found."""
#     file_id: str
#     error: GDriveError

# FileDetailsResponse = list[FolderContents] | list[FileDetails | FileErrorDetails] | FileDetails | FileErrorDetails