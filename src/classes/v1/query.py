# import Python's standard libraries
import enum

@enum.unique
class PublicKeyAlgorithm(str, enum.Enum):
    """The available algorithms for asymmetric encryption used for the API."""
    RSA = "rsa"