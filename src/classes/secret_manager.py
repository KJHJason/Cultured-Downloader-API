# For Google Cloud API Errors (Third-party libraries)
import google.api_core.exceptions as GoogleErrors

# For Google SM (Secret Manager) API (Third-party libraries)
from google.cloud import secretmanager
from google.cloud.secretmanager_v1.types import resources

# import local python libraries
if (__package__ is None or __package__ == ""):
    from initialise import CONSTANTS as C, crc32c
    from cloud_logger import CLOUD_LOGGER
else:
    from .initialise import CONSTANTS as C, crc32c
    from .cloud_logger import CLOUD_LOGGER

class SecretManager:
    """Creates a Secret Manager client that can be used to retrieve secrets from GCP."""
    def __init__(self) -> None:
        self.__SM_CLIENT = secretmanager.SecretManagerServiceClient.from_service_account_json(
            filename=C.CONFIG_DIR_PATH.joinpath("google-sm.json")
        )

    def get_secret_payload(self, secretID: str, 
                           versionID: str = "latest", decodeSecret: bool = True) -> str | bytes:
        """Get the secret payload from Google Cloud Secret Manager API.

        Args:
            secretID (str): 
                The ID of the secret.
            versionID (str): 
                The version ID of the secret.
            decodeSecret (bool): 
                If true, decode the returned secret bytes payload to string type. (Default: True)

        Returns:
            secretPayload (str|bytes): the secret payload
        """
        # construct the resource name of the secret version
        secretName = self.__SM_CLIENT.secret_version_path(C.GOOGLE_PROJECT_NAME, secretID, versionID)

        # get the secret version
        try:
            response = self.__SM_CLIENT.access_secret_version(request={"name": secretName})
        except (GoogleErrors.NotFound) as e:
            # secret version not found
            print("Error caught:")
            print(e, end="\n\n")
            return

        # return the secret payload
        secret = response.payload.data
        return secret.decode("utf-8") if (decodeSecret) else secret

    def upload_new_secret_version(self, secretID: str | bytes = None, secret: str = None, 
                                  destroyPastVer: bool = False, destroyOptimise: bool = False) -> resources.SecretVersion:
        """Uploads the new secret to Google Cloud Platform's Secret Manager API.

        Args:
            secretID (str): 
                The ID of the secret to upload
            secret (str|bytes): 
                The secret to upload
            destroyPastVer (bool): 
                Whether to destroy the past version of the secret or not
            destroyOptimise (bool): 
                Whether to optimise the process of destroying the past version of the secret
                Note: This should be True if the past versions have consistently been destroyed

        Returns:
            secretVersion (resources.SecretVersion): 
                The response from GCP Secret Manager API
        """
        # construct the secret path to the secret key ID
        secretPath = self.__SM_CLIENT.secret_path(C.GOOGLE_PROJECT_NAME, secretID)

        # encode the secret to bytes if secret is in string format
        if (isinstance(secret, str)):
            secret = secret.encode("utf-8")

        # calculate the payload crc32c checksum
        crc32cChecksum = crc32c(secret)

        # Add the secret version and send to Google Secret Management API
        response = self.__SM_CLIENT.add_secret_version(
            parent=secretPath, payload={"data": secret, "data_crc32c": crc32cChecksum}
        )

        # get the latest secret version and log the action
        latestVer = int(response.name.split("/")[-1])
        CLOUD_LOGGER.write_log_entry(
            logMessage={
                "message": f"Secret {secretID} (version {latestVer}) created successfully!",
                "details": response
            },
            severity="INFO"
        )

        # disable all past versions if destroyPastVer is True
        if (destroyPastVer):
            for version in range(latestVer - 1, 0, -1):
                secretVersionPath = self.__SM_CLIENT.secret_version_path(C.GOOGLE_PROJECT_NAME, secretID, version)
                try:
                    self.__SM_CLIENT.destroy_secret_version(request={"name": secretVersionPath})
                except (GoogleErrors.FailedPrecondition):
                    # key is already destroyed
                    if (destroyOptimise):
                        break

            CLOUD_LOGGER.write_log_entry(
                logMessage=f"Successfully destroyed all past versions of the secret {secretID}",
                severity="INFO"
            )

        return response

SECRET_MANAGER = SecretManager()

__all__ = [
    "SECRET_MANAGER"
]