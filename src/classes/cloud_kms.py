# For Google Cloud API Errors (Third-party libraries)
import google.api_core.exceptions as GoogleErrors

# For Google Cloud KMS (key management service) API (Third-party libraries)
from google.cloud import kms

# import third-party libraries
from cryptography.hazmat.primitives import hashes

# import Python's standard libraries
import json
import base64
import secrets
import warnings
from typing import Callable, Any
from binascii import Error as BinasciiError

# import local python libraries
if (__package__ is None or __package__ == ""):
    from exceptions import CRC32ChecksumError, DecryptionError
    from utils import rsa_encrypt
    from initialise import crc32c, CONSTANTS as C
    from secret_manager import SECRET_MANAGER
    from cloud_logger import CLOUD_LOGGER
    from app_constants import AppConstants as AC
else:
    from .exceptions import CRC32ChecksumError, DecryptionError
    from .utils import rsa_encrypt
    from .initialise import crc32c, CONSTANTS as C
    from .secret_manager import SECRET_MANAGER
    from .cloud_logger import CLOUD_LOGGER
    from .app_constants import AppConstants as AC

class GCP_KMS:
    """Creates an authenticated Cloud KMS client that can be used for cryptographic operations."""
    def __init__(self) -> None:
        self.__KMS_CLIENT = kms.KeyManagementServiceClient.from_service_account_info(
            info=json.loads(SECRET_MANAGER.get_secret_payload(secret_id="google-kms"))
        )
        self.__KEY_RING_ID = "api-sg"

    def log_failed_decryption(self, ciphertext: bytes, error: Any) -> None:
        """Logs the failed decryption attempt to the Cloud Logger and raise DecryptionError."""
        try:
            ciphertext_to_log = base64.urlsafe_b64encode(ciphertext).decode("utf-8")
        except:
            ciphertext_to_log = "Could not url-safe base64 encode the ciphertext..."

        CLOUD_LOGGER.info(
            content={
                "Decryption Error": str(error),
                "URL-base64 Encoded Ciphertext": ciphertext_to_log
            }
        )
        raise DecryptionError("Asymmetric Decryption failed.")

    def get_random_bytes(self, n_bytes: int, 
                         generate_from_hsm: bool | None = False, return_hex: bool | None = False) -> bytes | str:
        """Generate a random byte/hex string of length n_bytes that is cryptographically secure.

        Args:
            n_bytes (int): 
                The number of bytes to generate.
            generate_from_hsm (bool, optional):
                If True, the random bytes will be generated from GCP KMS's Cloud HSM. (Default: False)
            return_hex (bool, optional):
                If True, the random bytes will be returned as a hex string. (Default: False)

        Returns:
            bytes | str:
                The random bytes or random hex string.
        """
        if (n_bytes < 1):
            raise ValueError("n_bytes must be greater than 0!")

        # Since GCP KMS RNG Cloud HSM's minimum length is 8 bytes, 
        # fallback to secrets library if n_bytes is less than 8
        if (generate_from_hsm and n_bytes < 8):
            warnings.warn(
                message="GCP KMS does not accept n_bytes less than 8, falling back to secrets library...",
                category=RuntimeWarning
            )
            generate_from_hsm = False

        if (not generate_from_hsm):
            if (return_hex):
                return secrets.token_hex(n_bytes)
            else:
                return secrets.token_bytes(n_bytes)

        # Construct the location name
        location_name = self.__KMS_CLIENT.common_location_path(
            C.GOOGLE_PROJECT_NAME, C.GOOGLE_PROJECT_LOCATION
        )

        # Check if the number of bytes exceeds GCP KMS RNG Cloud HSM limit
        if (n_bytes > 1024):
            # if exceeded, make multiple API calls to generate the random bytes
            bytes_arr = []
            max_bytes = 1024
            num_of_max_bytes = n_bytes // max_bytes
            for _ in range(num_of_max_bytes):
                bytes_arr.append(
                    self.__KMS_CLIENT.generate_random_bytes(
                        request={
                            "location": location_name,
                            "length_bytes": max_bytes,
                            "protection_level": kms.ProtectionLevel.HSM
                        }
                    )
                )

            remainder = n_bytes % max_bytes
            if (remainder > 0):
                bytes_arr.append(
                    self.__KMS_CLIENT.generate_random_bytes(
                        request={
                            "location": location_name,
                            "length_bytes": remainder,
                            "protection_level": kms.ProtectionLevel.HSM
                        }
                    )
                )
            random_bytes = b"".join(bytes_arr)
        else:
            # Call the Google Cloud Platform API to generate a random byte string.
            random_bytes_response = self.__KMS_CLIENT.generate_random_bytes(
                request={
                    "location": location_name, 
                    "length_bytes": n_bytes, 
                    "protection_level": kms.ProtectionLevel.HSM
                }
            )
            random_bytes = random_bytes_response.data

        return random_bytes if (not return_hex) else random_bytes.hex()

    @property
    def KMS_CLIENT(self) -> kms.KeyManagementServiceClient:
        """Returns the KMS client."""
        return self.__KMS_CLIENT

    @property
    def KEY_RING_ID(self) -> str:
        """Returns the key ring ID."""
        return self.__KEY_RING_ID

class GCP_AESGCM(GCP_KMS):
    """Creates an authenticated GCP KMS client that uses AES-256-GCM for cryptographic operations."""
    def __init__(self, key_id: str | None = None) -> None:
        """Constructor for GCP_AESGCM

        Attributes:
            key_id (str):
                The default key ID to use for encryption/decryption (Defaults to None)
        """
        self.KEY_ID = key_id
        super().__init__()

    def symmetric_encrypt(self, plaintext: str | bytes, 
                          key_id: str | None = None, key_ring_id: str | None = None) -> bytes:
        """Using AES-256-GCM to encrypt the provided plaintext via GCP KMS.

        Args:
            plaintext (str|bytes): 
                the plaintext to encrypt
            key_ring_id (str): 
                the key ring ID (Defaults to KEY_RING_ID attribute of the object)
            key_id (str): 
                the key ID/name of the key (Defaults to KEY_ID attribute of the object)

        Returns:
            ciphertext (bytes): the ciphertext in bytes format

        Raises:
            ValueError:
                If the key_id is not provided
            CRC32ChecksumError:
                If the integrity checks failed
        """
        if (key_id is None):
            if (self.KEY_ID is None):
                raise ValueError("Please provide a key ID.")
            key_id = self.KEY_ID

        if (key_ring_id is None):
            key_ring_id = self.KEY_RING_ID

        if (isinstance(plaintext, str)):
            plaintext = plaintext.encode("utf-8")

        # Compute the plaintext's CRC32C checksum before sending it to Google Cloud KMS API
        plaintext_crc32c = crc32c(plaintext)

        # Construct the key version name
        key_version_name = self.KMS_CLIENT.crypto_key_path(
            C.GOOGLE_PROJECT_NAME, C.GOOGLE_PROJECT_LOCATION, key_ring_id, key_id
        )

        # Construct and send the request to Google Cloud KMS API to encrypt the plaintext
        response = self.KMS_CLIENT.encrypt(
            request={"name": key_version_name, "plaintext": plaintext, "plaintext_crc32c": plaintext_crc32c}
        )

        # Perform some integrity checks on the encrypted data that Google Cloud KMS API returned
        # details: https://cloud.google.com/kms/docs/data-integrity-guidelines
        if (not response.verified_plaintext_crc32c):
            # request sent to Google Cloud KMS API was corrupted in-transit
            raise CRC32ChecksumError("Plaintext CRC32C checksum does not match.")
        if (response.ciphertext_crc32c != crc32c(response.ciphertext)):
            # response received from Google Cloud KMS API was corrupted in-transit
            raise CRC32ChecksumError("Ciphertext CRC32C checksum does not match.")

        return response.ciphertext

    def symmetric_decrypt(self, ciphertext: bytes, key_id: str | None = None, 
                key_ring_id: str | None = None, decode: bool | None = False) -> str | bytes:
        """Using AES-256-GCM to decrypt the provided ciphertext via GCP KMS.

        Args:
            ciphertext (bytes): 
                the ciphertext to decrypt
            key_ring_id (str): 
                the key ring ID (Defaults to KEY_RING_ID attribute of the object)
            key_id (str): 
                the key ID/name of the key (Defaults to KEY_ID attribute of the object)
            decode (bool): 
                whether to decode the decrypted plaintext to string (Defaults to True)

        Returns:
            plaintext (str): the plaintext

        Raises:
            TypeError: 
                If the ciphertext is not bytes
            ValueError:
                If the key_id is not provided
            DecryptionError: 
                If the decryption failed
            CRC32ChecksumError: 
                If the integrity checks failed
        """
        if (isinstance(ciphertext, bytearray)):
            ciphertext = bytes(ciphertext)

        if (not isinstance(ciphertext, bytes)):
            print("cipher", ciphertext)
            raise TypeError(f"The ciphertext, {ciphertext} is in \"{type(ciphertext)}\" format. Please pass in a bytes type variable.")

        if (key_id is None):
            if (self.KEY_ID is None):
                raise ValueError("Please provide a key ID.")
            key_id = self.KEY_ID

        if (key_ring_id is None):
            key_ring_id = self.KEY_RING_ID

        # Construct the key version name
        key_version_name = self.KMS_CLIENT.crypto_key_path(
            C.GOOGLE_PROJECT_NAME, C.GOOGLE_PROJECT_LOCATION, key_ring_id, key_id
        )

        # compute the ciphertext's CRC32C checksum before sending it to Google Cloud KMS API
        ciphertext_crc32c = crc32c(ciphertext)

        # construct and send the request to Google Cloud KMS API to decrypt the ciphertext
        try:
            response = self.KMS_CLIENT.decrypt(
                request={"name": key_version_name, "ciphertext": ciphertext, "ciphertext_crc32c": ciphertext_crc32c}
            )
        except (GoogleErrors.InvalidArgument) as e:
            self.log_failed_decryption(ciphertext=ciphertext, error=e)

        # Perform a integrity check on the decrypted data that Google Cloud KMS API returned
        # details: https://cloud.google.com/kms/docs/data-integrity-guidelines
        if (response.plaintext_crc32c != crc32c(response.plaintext)):
            # response received from Google Cloud KMS API was corrupted in-transit
            raise CRC32ChecksumError("Plaintext CRC32C checksum does not match.")

        return response.plaintext.decode("utf-8") if (decode) else response.plaintext

class GCP_Asymmetric(GCP_KMS):
    """Creates an authenticated GCP KMS client that uses asymmetric cryptography operations."""
    def __init__(self, key_secret_id: str, key_id: str | None = None) -> None:
        """Constructor for GCP_Asymmetric

        Attributes:
            key_secret_id (str):
                the secret ID of the latest key version that is stored in GCP Secret Manager API
            key_id (str):
                The default key ID to use for encryption/decryption (Defaults to None)
        """
        self.__KEY_VERSION_SECRET_ID = key_secret_id
        self.KEY_ID = key_id
        super().__init__()

    def get_latest_ver(self) -> int:
        """Returns the latest version of the key version that is stored in GCP Secret Manager API."""
        return int(SECRET_MANAGER.get_secret_payload(secret_id=self.__KEY_VERSION_SECRET_ID))

    def get_public_key(self, key_id: str | None = None, 
                       key_ring_id: str | None = None, version: int | None = None) -> str:
        """Returns the public key of the provided key ID.

        Args:
            key_id (str): 
                the key ID/name of the key (Defaults to KEY_ID attribute of the object)
            key_ring_id (str): 
                the key ring ID (Defaults to KEY_RING_ID attribute of the object)
            version (int):
                the key version (Defaults to the latest version)

        Returns:
            public_key (str):
                The public key which will have to be serialised to a PEM format later
                in order to use it for cryptographic operations.

        Raises:
            ValueError:
                If the key_id is not provided
        """
        if (key_id is None):
            if (self.KEY_ID is None):
                raise ValueError("Please provide a key ID.")
            key_id = self.KEY_ID

        if (key_ring_id is None):
            key_ring_id = self.KEY_RING_ID

        if (version is None):
            version = self.get_latest_ver()

        # Construct the key version name
        key_version_name = self.KMS_CLIENT.crypto_key_version_path(
            C.GOOGLE_PROJECT_NAME, C.GOOGLE_PROJECT_LOCATION, key_ring_id, key_id, version
        )

        # Get the public key from Google Cloud KMS API
        return self.KMS_CLIENT.get_public_key(request={"name": key_version_name}).pem

class GCP_RSA(GCP_Asymmetric):
    """Creates an authenticated GCP KMS client that uses RSA-OAEP-SHA for cryptographic operations."""
    def __init__(self, key_secret_id: str, key_id: str | None = None, 
                 digest_method: Callable | None = hashes.SHA512) -> None:
        """Constructor for GCP_RSA

        Attributes:
            key_secret_id (str):
                the secret ID of the latest key version that is stored in GCP Secret Manager API
            digest_method (Callable, Optional):
                The digest method to use (Defaults to SHA512) which must be part of the cryptography module
        """
        if (not issubclass(digest_method, hashes.HashAlgorithm)):
            raise TypeError("digest method must be a subclass of cryptography.hazmat.primitives.hashes.HashAlgorithm")

        self.__DIGEST_METHOD = digest_method
        super().__init__(key_id=key_id, key_secret_id=key_secret_id)

    def asymmetric_encrypt(self, plaintext: str | bytes, key_id: str | None = None,
                key_ring_id: str | None = None, version: int | None = None) -> bytes:
        """Encrypts the plaintext using RSA-OAEP-SHA via GCP KMS API.

        Args:
            plaintext (str|bytes):
                The plaintext to encrypt
            key_id (str):
                The key ID/name of the key (Defaults to KEY_ID attribute of the object)
            key_ring_id (str):
                The key ring ID (Defaults to KEY_RING_ID attribute of the object)
            version (int):
                The key version (Defaults to the latest version)

        Returns:
            The ciphertext (bytes)

        Raises:
            ValueError:
                If the key_id is not provided
        """
        if (key_id is None):
            if (self.KEY_ID is None):
                raise ValueError("Please provide a key ID.")
            key_id = self.KEY_ID

        if (key_ring_id is None):
            key_ring_id = self.KEY_RING_ID

        if (version is None):
            version = self.get_latest_ver()

        if (isinstance(plaintext, str)):
            plaintext = plaintext.encode("utf-8")

        # Encrypt the plaintext with the public key
        public_key = self.get_public_key(key_id=key_id, key_ring_id=key_ring_id, version=version)
        return rsa_encrypt(plaintext=plaintext, public_key=public_key, digest_method=self.__DIGEST_METHOD)

    def asymmetric_decrypt(self, ciphertext: bytes, key_id: str | None = None, 
                key_ring_id: str | None = None, version: int | None = None, decode: bool | None = False) -> bytes | str:
        """Encrypts the plaintext using RSA-OAEP-SHA via GCP KMS API.

        Args:
            ciphertext (bytes):
                The ciphertext to decrypt
            key_id (str):
                The key ID/name of the key (Defaults to KEY_ID attribute of the object)
            key_ring_id (str):
                The key ring ID (Defaults to KEY_RING_ID attribute of the object)
            version (int):
                The key version (Defaults to the latest version)
            decode (bool):
                If True, the decrypted plaintext is returned as a string (Defaults to False)

        Returns:
            The plaintext (bytes|str)

        Raises:
            DecryptionError: 
                If the decryption failed
            ValueError:
                If the key_id is not provided
        """
        if (key_id is None):
            if (self.KEY_ID is None):
                raise ValueError("Please provide a key ID.")
            key_id = self.KEY_ID

        if (key_ring_id is None):
            key_ring_id = self.KEY_RING_ID

        if (version is None):
            version = self.get_latest_ver()

        # Construct the key version name
        key_version_name = self.KMS_CLIENT.crypto_key_version_path(
            C.GOOGLE_PROJECT_NAME, C.GOOGLE_PROJECT_LOCATION, key_ring_id, key_id, version
        )

        # Compute the ciphertext's CRC32C checksum before sending it to Google Cloud KMS API
        ciphertext_crc32c = crc32c(ciphertext)

        # send the request to Google Cloud KMS API to decrypt the ciphertext
        try:
            response = self.KMS_CLIENT.asymmetric_decrypt(
                request={"name": key_version_name, "ciphertext": ciphertext, "ciphertext_crc32c": ciphertext_crc32c}
            )
        except (GoogleErrors.InvalidArgument) as e:
            self.log_failed_decryption(ciphertext=ciphertext, error=e)

        # Perform a integrity check on the decrypted data that Google Cloud KMS API returned
        # details: https://cloud.google.com/kms/docs/data-integrity-guidelines
        if (not response.verified_ciphertext_crc32c):
            # request sent to Google Cloud KMS API was corrupted in-transit
            raise CRC32ChecksumError("Ciphertext CRC32C checksum does not match.")
        if (response.plaintext_crc32c != crc32c(response.plaintext)):
            # response received from Google Cloud KMS API was corrupted in-transit
            raise CRC32ChecksumError("Plaintext CRC32C checksum does not match.")

        return response.plaintext if (not decode) else response.plaintext.decode("utf-8")

class UserCookie(GCP_RSA, GCP_AESGCM):
    """Creates an authenticated GCP KMS client that uses RSA-OAEP-SHA and 
    AES-256-GCM for cryptographic operations with the user's cookies.
    """
    def __init__(self, digest_method: Callable | None = hashes.SHA512) -> None:
        """Constructor for UserCookie

        Attributes:
            digest_method (Callable, Optional):
                The digest method to use (Defaults to SHA512) which must be part of the cryptography module
        """
        self.__RSA_KEY = AC.RSA_KEY_ID
        self.__AES_KEY = AC.COOKIE_ENCRYPTION_KEY
        super().__init__(digest_method=digest_method, key_secret_id=AC.RSA_VERSION_SECRET_ID)

    def get_api_rsa_public_key(self) -> str:
        """Gets the RSA public key of the Cultured Downloader API."""
        latest_ver = int(SECRET_MANAGER.get_secret_payload(secret_id=AC.RSA_VERSION_SECRET_ID))
        return self.get_public_key(key_id=self.__RSA_KEY, version=latest_ver)

    def encrypt_cookie_data(self, cookie_data: str | dict | bytes, 
                            user_public_key: str, digest_method: str | None = None) -> str:
        """Encrypts the cookie data using AES-256-GCM via GCP KMS API.

        Args:
            cookie_data (str, dict, bytes):
                The cookie_data to encrypt
            user_public_key (str):
                The public key of the user
            digest_method (str):
                The digest method to use (Defaults to SHA512) for
                RSA-OAEP-SHA encryption which must be part of the cryptography module.

        Returns:
            The base64 encoded ciphertext in string format (utf-8 decoded).

        Raises:
            ValueError:
                If the key_id is not provided
            CRC32ChecksumError:
                If the integrity checks failed
        """
        if (isinstance(cookie_data, str)):
            cookie_data = cookie_data.encode("utf-8")
        elif (isinstance(cookie_data, dict)):
            cookie_data = json.dumps(cookie_data).encode("utf-8")

        encrypted_cookie_data = rsa_encrypt(
            plaintext=self.symmetric_encrypt(
                plaintext=cookie_data,
                key_id=self.__AES_KEY
            ),
            public_key=user_public_key,
            digest_method=digest_method
        )
        return base64.b64encode(encrypted_cookie_data).decode("utf-8")

    def decrypt_cookie_data(self, encrypted_cookie_data: bytes, 
                            user_public_key: str, digest_method: str | None = None) -> str:
        """Decrypts the cookie data using AES-256-GCM via GCP KMS API.

        Args:
            encrypted_cookie_data (bytes):
                The encrypted cookie data to decrypt
            user_public_key (str):
                The public key of the user
            digest_method (str):
                The digest method to use (Defaults to SHA512) for
                RSA-OAEP-SHA encryption which must be part of the cryptography module.

        Returns:
            The base64 encoded ciphertext in string format (utf-8 decoded)

        Raises:
            ValueError:
                If the key_id is not provided
            CRC32ChecksumError:
                If the integrity checks failed
        """
        cookie_data = rsa_encrypt(
            plaintext=self.symmetric_decrypt(
                ciphertext=encrypted_cookie_data,
                key_id=self.__AES_KEY
            ),
            public_key=user_public_key,
            digest_method=digest_method
        )
        return base64.b64encode(cookie_data).decode("utf-8")

    def decrypt_cookie_payload(self, encrypted_cookie: bytes) -> dict[str, bytes]:
        """Decrypts the cookie payload that was sent to the API using the API's private key.

        Args:
            encrypted_cookie (bytes): 
                The cookie data to decrypt.

        Returns:
            The decrypted cookie data (dict).
        """
        try:
            encrypted_cookie = base64.b64decode(encrypted_cookie)
        except (BinasciiError, ValueError, TypeError):
            return {"error": "Failed to base64 decode the cookie ciphertext."}

        try:
            decrypted_cookie = self.asymmetric_decrypt(ciphertext=encrypted_cookie, key_id=self.__RSA_KEY)
        except (DecryptionError):
            return {"error": "Failed to decrypt the cookie ciphertext."}

        return {"payload": decrypted_cookie}

USER_COOKIE = UserCookie()

__all__ = [
    "GCP_RSA",
    "GCP_AESGCM",
    "USER_COOKIE"
]