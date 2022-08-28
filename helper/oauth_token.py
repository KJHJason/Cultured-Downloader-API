# import third party libraries
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.auth.exceptions import RefreshError

# import python standard libraries
import pathlib
import sys
import json
from importlib.util import spec_from_file_location, module_from_spec

# import local python libraries
FILE_PATH = pathlib.Path(__file__).parent.absolute()
PYTHON_FILES_PATH = FILE_PATH.parent.joinpath("src", "classes")

# add to sys path so that cloud_logger.py can be imported by secret_manager.py
sys.path.append(str(PYTHON_FILES_PATH))

# import secret_manager.py local python module using absolute path
SM_PY_FILE = PYTHON_FILES_PATH.joinpath("secret_manager.py")
spec = spec_from_file_location("secret_manager", str(SM_PY_FILE))
secret_manager = module_from_spec(spec)
sys.modules[spec.name] = secret_manager
spec.loader.exec_module(secret_manager)

C = secret_manager.C
SECRET_MANAGER = secret_manager.SECRET_MANAGER

def shutdown() -> None:
    """
    For UX, prints shutdown message.
    """
    print()
    print("Shutting down...")
    input("Please press ENTER to exit...")
    print()

def create_token() -> None:
    """
    Will try to initialise Google API by trying to authenticate with token.json
    stored in Google Cloud Platform Secret Manager API.
    On success, will not ask for credentials again.
    Otherwise, will ask to authenticate with Google.
    """
    generatedNewToken = False
    creds = None

    try:
        GOOGLE_TOKEN = json.loads(
            SECRET_MANAGER.get_secret_payload(
                secretID=C.OAUTH_TOKEN_SECRET_NAME
            )
        )
    except (json.decoder.JSONDecodeError, TypeError):
        GOOGLE_TOKEN = None

    GOOGLE_OAUTH_CLIENT = json.loads(
        SECRET_MANAGER.get_secret_payload(
            secretID=C.OAUTH_CLIENT_SECRET_NAME
        )
    )

    # The file google-token.json stores the user's access and refresh tokens,
    # and is stored in Google Secret Manager API.
    # It is created automatically when the authorization flow 
    # completes for the first time and will be saved to Google Secret Manager API.
    if (GOOGLE_TOKEN is not None):
        try:
            creds = Credentials.from_authorized_user_info(GOOGLE_TOKEN, C.GOOGLE_DRIVE_SCOPES)
        except (RefreshError):
            print("Token is no longer valid as there is a refresh error!\n")
    else:
        print("No token found.\n")

    # If there are no (valid) credentials available, let the user log in.
    if (creds is None or not creds.valid):
        if (creds and creds.expired and creds.refresh_token):
            print("Token is valid but might expire soon, refreshing token instead...", end="")
            creds.refresh(Request())
            print("\r\033[KRefreshed token!\n")
        else:
            print("Token is expired or invalid!\n")
            flow = InstalledAppFlow.from_client_config(GOOGLE_OAUTH_CLIENT, C.GOOGLE_DRIVE_SCOPES)
            creds = flow.run_local_server(port=8080)

        # For print message to indicate if the token is 
        # newly uploaded or loaded from GCP Secret Manager API
        generatedNewToken = True

        while (1):
            destroyAllPastVer = input("Do you want to DESTROY all past versions? (Y/n): ").lower().strip()
            if (destroyAllPastVer not in ("y", "n", "")):
                print("Please enter a valid input!")
                continue
            else:
                destroyAllPastVer = True if (destroyAllPastVer != "n") else False
                break

        # Save the credentials for the next run to Google Secret Manager API
        print(f"Adding new secret version to the secret ID, {C.OAUTH_TOKEN_SECRET_NAME}...", end="")
        response = SECRET_MANAGER.upload_new_secret_version(
            secretID=C.OAUTH_TOKEN_SECRET_NAME,
            secret=creds.to_json(),
            destroyPastVer=destroyAllPastVer,
            destroyOptimise=True
        )
        print(f"\rNew secret version, {C.OAUTH_TOKEN_SECRET_NAME}, created:", response.name, "\n")

    try:
        # Build the Google Drive service from the credentials
        with build("drive", "v3", credentials=creds):
            print(f"Status OK! {'Generated' if (generatedNewToken) else 'Loaded'} token.json is valid.")
    except (HttpError) as error:
        print(f"\nAn error has occurred:\n{error}")
        print()
        sys.exit(1)

def main() -> None:
    while (1):
        try:
            prompt = input("Do you want to save a new Google OAuth2 token? (y/N): ").lower().strip()
        except (KeyboardInterrupt):
            shutdown()
            return

        if (prompt not in ("y", "n", "")):
            print("Invalid input. Please try again.", end="\n\n")
            continue
        elif (prompt != "y"):
            print("\nShutting down...")
            input("Please press ENTER to exit...")
            return
        else:
            print(f"Will proceed to generate a new Google OAuth2 token, if it is invalid...", end="\n\n")
            break

    create_token()

if (__name__ == "__main__"):
    main()