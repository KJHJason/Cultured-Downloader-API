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
from typing import NoReturn
from importlib.util import spec_from_file_location, module_from_spec

# import local python libraries
FILE_PATH = pathlib.Path(__file__).parent.absolute()
PYTHON_FILES_PATH = FILE_PATH.parent.joinpath("src", "classes")

# add to sys path so that cloud_logger.py can be imported by secret_manager.py
sys.path.append(str(PYTHON_FILES_PATH))

# import secret_manager.py local python module using absolute path
KMS_PY_FILE = PYTHON_FILES_PATH.joinpath("cloud_kms.py")
spec = spec_from_file_location("cloud_kms", str(KMS_PY_FILE))
cloud_kms = module_from_spec(spec)
sys.modules[spec.name] = cloud_kms
spec.loader.exec_module(cloud_kms)

C = cloud_kms.C
SECRET_MANAGER = cloud_kms.SECRET_MANAGER
GCP_KMS = cloud_kms.GCP_KMS()

def shutdown() -> NoReturn:
    """For UX, prints shutdown message."""
    print()
    print("Shutting down...")
    input("Please press ENTER to exit...")
    print()
    sys.exit(0)

def get_input(prompt: str, availableInputs: tuple[str] | list[str], 
              default: str | None = None, extraInfo: str | None = None) -> str:
    """Gets input from user.

    Args:
        prompt (str):
            The prompt to display to the user.
        availableInputs (tuple[str]|list[str]):
            The available inputs that the user can enter.
        default (str|None):
            The default input to return if the user enters nothing.
        extraInfo (str|None):
            Extra information to display to the user before the prompt.

    Returns:
        str: 
            The user's input.

    Raises:
        TypeError:
            If the supplied availableInputs argument is not a tuple or a list.
    """
    if (not isinstance(availableInputs, tuple | list)):
        raise TypeError("availableInputs must be a tuple or list")

    if (isinstance(availableInputs, list)):
        availableInputs = tuple(availableInputs)

    while (1):
        if (extraInfo is not None):
            print(extraInfo)

        response = input(prompt).lower().strip()
        if (response == "" and default is not None):
            return default
        elif (response not in availableInputs):
            print("Invalid input. Please try again.", end="\n\n")
            continue
        else:
            return response

def generate_new_oauth_token() -> None:
    """Will try to initialise Google API by trying to authenticate with token.json
    stored in Google Cloud Platform Secret Manager API.
    On success, will not ask for credentials again.
    Otherwise, will ask to authenticate with Google.
    """
    try:
        choice = get_input(
            prompt="Do you want to save a new Google OAuth2 token? (y/N): ",
            availableInputs=("y", "n"),
            default="n"
        )
    except (KeyboardInterrupt):
        return

    if (choice != "y"):
        print("\nCancelling Google OAuth2 token creation...")
        return
    else:
        print(f"Will proceed to generate a new Google OAuth2 token, if it is invalid...")

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
            creds = Credentials.from_authorized_user_info(GOOGLE_TOKEN, C.GOOGLE_OAUTH_SCOPES)
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
            flow = InstalledAppFlow.from_client_config(GOOGLE_OAUTH_CLIENT, C.GOOGLE_OAUTH_SCOPES)
            creds = flow.run_local_server(port=8080)

        # For print message to indicate if the token is 
        # newly uploaded or loaded from GCP Secret Manager API
        generatedNewToken = True

        try:
            destroyAllPastVer = get_input(
                prompt="Do you want to DESTROY all past versions? (Y/n): ",
                availableInputs=("y", "n"),
                default="Y"
            )
        except (KeyboardInterrupt):
            print("\nCancelling Google OAuth2 token creation...")
            return

        destroyAllPastVer = True if (destroyAllPastVer != "n") else False

        # Save the credentials for the next run to Google Secret Manager API
        print(f"Adding new secret version to the secret ID, {C.OAUTH_TOKEN_SECRET_NAME}...", end="")
        response = SECRET_MANAGER.upload_new_secret_version(
            secretID=C.OAUTH_TOKEN_SECRET_NAME,
            secret=creds.to_json(),
            destroyPastVer=destroyAllPastVer,
            destroy_optimise=True
        )
        print(f"\rNew secret version, {C.OAUTH_TOKEN_SECRET_NAME}, created:", response.name)

    try:
        # Build the Google Drive service from the credentials
        with build("drive", "v3", credentials=creds) as _:
            print(f"Status OK! {'Generated' if (generatedNewToken) else 'Loaded'} token.json is valid.")
    except (HttpError) as error:
        print(f"\nAn error has occurred:\n{error}")
        print()
        sys.exit(1)

def flask_session() -> None:
    FLASK_SECRET_KEY_ID = "flask-secret-key" 
    FLASK_SESSION_SALT_ID = "flask-session-salt"
    while (1):
        print("""
--------- Flask Session Configurations Menu ---------
1. Generate a new secret key using GCP KMS API
2. Generate a new 64 bytes salt
3. View the secret key from GCP Secret Manager API
4. View the salt from GCP Secret Manager API
X. Back to main menu
-----------------------------------------------------""")

        try:
            choice = get_input(
                prompt="Please enter your choice: ",
                availableInputs=("1", "2", "3", "4", "x")
            )
        except (KeyboardInterrupt):
            return

        if (choice == "x"):
            return
        elif (choice == "1"):
            try:
                generatePrompt = get_input(
                    prompt="Do you want to generate a new secret key? (y/N): ",
                    availableInputs=("y", "n"),
                    default="n"
                )
            except (KeyboardInterrupt):
                print("Generation of a new key will be aborted...")
                continue

            if (generatePrompt != "y"):
                print("\nCancelling key generation...", end="\n\n")
                continue

            try:
                destroyAllPastVer = get_input(
                    prompt="Do you want to DESTROY all past versions? (Y/n): ",
                    availableInputs=("y", "n"),
                    default="Y"
                )
            except (KeyboardInterrupt):
                print("Generation of a new key will be aborted...")
                continue
            destroyAllPastVer = True if (destroyAllPastVer != "n") else False

            print("Generating a new Flask secret key...", end="")
            response = SECRET_MANAGER.upload_new_secret_version(
                secretID=FLASK_SECRET_KEY_ID,
                secret=GCP_KMS.get_random_bytes(
                    nBytes=512, 
                    generateFromHSM=True
                ),
                destroyPastVer=destroyAllPastVer,
                destroy_optimise=True
            )
            print(f"\rGenerated the new Flask secret key at \"{response.name}\"!", end="\n\n")

        elif (choice == "2"):
            try:
                generateSalt = get_input(
                    prompt="Enter command (y/N): ",
                    availableInputs=("y", "n"),
                    default="n",
                    extraInfo="Generate and add a new salt for the "
                              "Flask session cookie to Google Secret Manager API?"
                )
            except (KeyboardInterrupt):
                print("Generation of a new salt will be aborted...")
                continue

            if (generateSalt != "y"):
                print("\nCancelling salt generation...", end="\n\n")
                continue

            try:
                destroyAllPastVer = get_input(
                    prompt="Do you want to DESTROY all past versions? (Y/n): ",
                    availableInputs=("y", "n"),
                    default="Y"
                )
            except (KeyboardInterrupt):
                print("Generation of a new salt will be aborted...")
                continue
            destroyAllPastVer = True if (destroyAllPastVer != "n") else False

            SECRET_MANAGER.upload_new_secret_version(
                secretID=FLASK_SESSION_SALT_ID,
                secret=GCP_KMS.get_random_bytes(
                    nBytes=64, 
                    generateFromHSM=True
                ),
                destroyPastVer=destroyAllPastVer,
                destroy_optimise=True
            )
            print("Generated a new Flask session salt!")

        elif (choice == "3" or choice == "4"):
            secretType = "Flask secret key" if (choice == "3") \
                                            else "Flask session salt"
            try:
                viewInHex = get_input(
                    prompt=f"Do you want to view the {secretType} in hexadecimal? (Y/n): ",
                    availableInputs=("y", "n"),
                    default="y"
                )
            except (KeyboardInterrupt):
                print(f"Viewing of the {secretType} will be aborted...")
                continue

            secretPayload = SECRET_MANAGER.get_secret_payload(
                secretID=FLASK_SECRET_KEY_ID if (choice == "3") \
                                             else FLASK_SESSION_SALT_ID,
                decodeSecret=False
            )
            if (viewInHex != "n"):
                secretPayload = secretPayload.hex()
            print(f"Generated {secretType} that is currently in use:", secretPayload, sep="\n")
            del secretPayload

def main() -> None:
    while (1):
        print("""
---- Cultured Downloader Web App Menu ----
1. Generate a new Google OAuth2 token
2. Flask Session Configurations menu
X. Shutdown program
------------------------------------------""")
        try:
            menuChoice = get_input(
                prompt="Enter command: ",
                availableInputs=("1", "2", "x")
            )
        except (KeyboardInterrupt):
            shutdown()
        if (menuChoice == "x"):
            shutdown()
        elif (menuChoice == "1"):
            generate_new_oauth_token()
        elif (menuChoice == "2"):
            flask_session()

if (__name__ == "__main__"):
    main()