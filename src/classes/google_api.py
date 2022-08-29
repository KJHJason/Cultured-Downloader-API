# import third-party libraries
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import aiohttp

# import Python's standard libraries
import json

# import local python libraries
if (__package__ is None or __package__ == ""):
    from initialise import CONSTANTS as C
    from secret_manager import SECRET_MANAGER
    from app_constants import APP_CONSTANTS as AC
    from cloud_logger import CLOUD_LOGGER
else:
    from .initialise import CONSTANTS as C
    from .secret_manager import SECRET_MANAGER
    from .app_constants import APP_CONSTANTS as AC
    from .cloud_logger import CLOUD_LOGGER

class GoogleOAuth2:
    def __init__(self) -> None:
        self.__CREDENTIALS = Credentials.from_authorized_user_info(
            info=json.loads(
                SECRET_MANAGER.get_secret_payload(
                    secretID=C.OAUTH_TOKEN_SECRET_NAME
                )
            ), 
            scopes=C.GOOGLE_OAUTH_SCOPES
        )

    @property
    def CREDENTIALS(self) -> Credentials:
        return self.__CREDENTIALS

class GoogleDrive(GoogleOAuth2):
    def __init__(self) -> None:
        super().__init__()
        self.__DRIVE_SERVICE = build(
            serviceName="drive",
            version="v3",
            credentials=self.CREDENTIALS
        )

        # add some restrictions to prevent the user from reading my own gdrive files
        self.__QUERY = "(visibility='anyoneCanFind' or visibility='anyoneWithLink')"\
                       " and not ('kuanjunhaojason@gmail.com' in owners)"

    def get_folder_contents(self, folderID: str, resourceKey:str | None = None) -> list:
        """Sends a request to the Google Drive API to get the 
        json representation of the folder URL's directory structure

        Args:
            folderID (str): 
                The ID of the Google Drive URL

        Returns:
            dict:
                The json representation of the gdrive URL's directory structure
        """
        files = []
        pageToken = None
        while (1):
            try:
                response = self.__DRIVE_SERVICE.files().list(
                    q=" ".join((f"'{folderID}' in parents and", self.__QUERY)),
                    fields="nextPageToken, files(id, name, mimeType)",
                    pageToken=pageToken
                ).execute()
            except (HttpError) as e:
                CLOUD_LOGGER.warning(
                    content={
                        "message": f"error retrieving folder, {folderID}",
                        "error": str(e)
                    }
                )
                return {
                    "error": 
                        "could not retrieve folder contents from Google Drive API... "
                        "please try again later."
                }

            for file in response.get("files", []):
                files.append(file)

            pageToken = response.get("nextPageToken", None)
            if (pageToken is None):
                break

        return {"directory": files}

    async def get_file_details(self, fileID: str) -> dict:
        """Sends a request to the Google Drive API to
        get the json representation of the file details.

        Note that due to privacy reasons, a HTTP request will be sent instead of using
        the in-built Google Drive API, service.files().get(fileId=fileID).execute().

        Args:
            fileID (str): 
                The ID of the Google Drive file

        Returns:
            dict:
                The json representation of the file's details
        """
        gdriveAPIToken = SECRET_MANAGER.get_secret_payload(secretID="gdrive-api-token")
        async with aiohttp.ClientSession(headers=AC.DRIVE_REQ_HEADERS) as session:
            try:
                url = f"https://www.googleapis.com/drive/v3/files/{fileID}?key={gdriveAPIToken}"
                async with session.get(url=url) as response:
                    jsonResponse = await response.json()
                    return {"file": jsonResponse}
            except (
                aiohttp.ClientConnectionError, 
                aiohttp.ClientConnectorError, 
                aiohttp.ServerConnectionError,
                aiohttp.ClientSSLError,
                aiohttp.ClientResponseError,
                aiohttp.ContentTypeError,
                aiohttp.TooManyRedirects,
                aiohttp.ClientPayloadError
            ) as e:
                CLOUD_LOGGER.warning(
                    content={
                        "message": f"error retrieving file, {fileID}",
                        "error": str(e)
                    }
                )
                return {
                    "error": 
                        "could not retrieve file details from Google Drive API... "
                        "please try again later."
                    }