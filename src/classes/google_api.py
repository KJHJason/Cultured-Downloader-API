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
    """Creates the base Google API service object that can be used for creating
    authenticated API calls to other Google APIs that requires Google OAuth2 authentication"""
    def __init__(self) -> None:
        self.__CREDENTIALS = Credentials.from_authorized_user_info(
            info=json.loads(
                SECRET_MANAGER.get_secret_payload(
                    secret_id=C.OAUTH_TOKEN_SECRET_NAME
                )
            ), 
            scopes=C.GOOGLE_OAUTH_SCOPES
        )

    @property
    def CREDENTIALS(self) -> Credentials:
        """Returns the credentials object that can be used to build other 
        authenticated Google API objects via the googleapiclient.discovery.build function"""
        return self.__CREDENTIALS

class GoogleDrive(GoogleOAuth2):
    """Creates an authenticated Google Drive Client that 
    can be used for communicating with Google Drive API v3."""
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

    def get_folder_contents(self, folder_id: str) -> list:
        """Sends a request to the Google Drive API to get the 
        json representation of the folder URL's directory structure

        Args:
            folder_id (str): 
                The ID of the Google Drive URL

        Returns:
            dict:
                The json representation of the gdrive URL's directory structure
        """
        files = []
        page_token = None
        while (1):
            try:
                response = self.__DRIVE_SERVICE.files().list(
                    q=" ".join((f"'{folder_id}' in parents and", self.__QUERY)),
                    fields="nextPageToken, files(id, name, mimeType)",
                    page_token=page_token
                ).execute()
            except (HttpError) as e:
                CLOUD_LOGGER.warning(
                    content={
                        "message": f"error retrieving folder, {folder_id}",
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

            page_token = response.get("nextPageToken", None)
            if (page_token is None):
                break

        return {"directory": files}

    async def get_file_details(self, file_id: str) -> dict:
        """Sends a request to the Google Drive API to
        get the json representation of the file details.

        Note that due to privacy reasons, a HTTP request will be sent instead of using
        the in-built Google Drive API, service.files().get(file_id=file_id).execute().

        Args:
            file_id (str): 
                The ID of the Google Drive file

        Returns:
            dict:
                The json representation of the file's details
        """
        gdrive_api_token = SECRET_MANAGER.get_secret_payload(secret_id="gdrive-api-token")
        async with aiohttp.ClientSession(headers=AC.DRIVE_REQ_HEADERS) as session:
            try:
                url = f"https://www.googleapis.com/drive/v3/files/{file_id}?key={gdrive_api_token}"
                async with session.get(url=url) as response:
                    json_response = await response.json()
                    return {"file": json_response}
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
                        "message": f"error retrieving file, {file_id}",
                        "error": str(e)
                    }
                )
                return {
                    "error": 
                        "could not retrieve file details from Google Drive API... "
                        "please try again later."
                    }