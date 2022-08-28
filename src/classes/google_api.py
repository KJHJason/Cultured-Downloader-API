# import third-party libraries
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpErro
import aiohttp

# import Python's standard libraries
import asyncio
import json

# import local python libraries
if (__package__ is None or __package__ == ""):
    from initialise import CONSTANTS as C
    from secret_manager import SECRET_MANAGER
    from cloud_logger import CLOUD_LOGGER
else:
    from .initialise import CONSTANTS as C
    from .secret_manager import SECRET_MANAGER
    from .cloud_logger import CLOUD_LOGGER

class GoogleOAuth2:
    def __init__(self) -> None:
        self.__CREDENTIALS = Credentials.from_authorized_user_info(
            info=json.loads(
                SECRET_MANAGER.get_secret_payload(
                    secretID=C.OAUTH_TOKEN_SECRET_NAME
                )
            ), 
            scopes=C.GOOGLE_DRIVE_SCOPES
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

    async def list_files(self, driveID: str, gdriveType: str) -> list:
        """Sends a request to the Google Drive API to get the 
        json representation of the gdrive URL's directory structure

        Args:
            gdriveID (str): 
                The ID of the Google Drive URL
            gdriveType (str):
                The type of the Google Drive URL

        Returns:
            dict:
                The json representation of the gdrive URL's directory structure
        """
        if (gdriveType == "file"):
            url = f"https://www.googleapis.com/drive/v3/files/{gdriveID}?key={AC.GDRIVE_API_TOKEN}"
        else:
            url = f"https://www.googleapis.com/drive/v3/files?q=%27{gdriveID}%27+in+parents&key={AC.GDRIVE_API_TOKEN}"

        try:
            return requests.get(url, headers=AC.REQ_HEADERS).json()
        except (HTTPError, ConnectionError, Timeout, RequestException) as e:
            return {"error": str(e)}

# test codes
if (__name__ == "__main__"):
    gdrive = GoogleDrive()
    print(gdrive.list_files(driveID="1kKSClgeP1bjmWiKxDcMfoXoUu7XsNtCJ"))