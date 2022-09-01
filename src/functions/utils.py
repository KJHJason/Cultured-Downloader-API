# import third-party libraries
from fastapi import Request, Response
from fastapi.templating import Jinja2Templates

# import python standard libraries
import time
import re
import secrets

# import local python libraries
from classes import APP_CONSTANTS as AC, CONSTANTS as C

def format_server_time() -> str:
    """Demo function to format the server time."""
    serverTime = time.localtime()
    return time.strftime("%I:%M:%S %p", serverTime)

def generate_nonce() -> str:
    """Generate a random nonce.

    Returns:
        str:
            The random 256 bits base64 encoded nonce
    """
    return secrets.token_urlsafe(32)

def parse_csp(csp: dict) -> tuple[str, str]:
    """Parse the CSP dictionary into a string.

    Args:
        csp (dict): 
            The CSP dictionary

    Returns:
        str:
            The CSP string
    """
    parsed_csp = ""
    for key, value in csp.items():
        parsed_csp += "{key} {values}".format(
            key=key,
            values=" ".join(value)
        )
        if (key == "script-src"):
            parsed_csp += f" 'nonce-{generate_nonce()}'"
        else:
            parsed_csp += "; "
    return parsed_csp + ";"

def add_csp_header_to_response(response: Response) -> None:
    """Adds the CSP header to the response.

    Args:
        response (Response): 
            The response object

    Returns:
        None
    """
    response.headers["Content-Security-Policy"] = parse_csp(AC.CSP_HEADER)

def csp_nonce(response: Response) -> str:
    """Retrieves the CSP nonce from the header"""
    csp_header = response.headers.get(key="Content-Security-Policy", default="")
    if ("nonce" in csp_header):
        return re.search(AC.NONCE_REGEX, csp_header).group(1)
    return ""

def get_user_ip(request: Request) -> str:
    """Returns the user's IP address as a string.

    For cloudflare proxy, we need to get from the request headers:
    https://developers.cloudflare.com/fundamentals/get-started/reference/http-request-headers/

    Args:
        request (Request): 
            The request object

    Returns:
        str:
            The user's IP address (127.0.0.1 if not found)
    """
    cloudflareProxy = request.headers.get(key="CF-Connecting-IP", default=None)
    if (cloudflareProxy is not None):
        return cloudflareProxy

    requestIP = request.client
    if (requestIP is not None):
        return requestIP.host

    return "127.0.0.1"

def get_jinja2_templates() -> Jinja2Templates:
    """Returns the Jinja2Templates object.

    Returns:
        Jinja2Templates:
            The Jinja2Templates object
    """
    templates = Jinja2Templates(
    directory=str(C.ROOT_DIR_PATH.joinpath("templates")), 
    trim_blocks=True,
    lstrip_blocks=True
    )
    templates.env.globals.update(
        csp_nonce=csp_nonce
    )
    templates.env.globals.update(
        get_user_ip=get_user_ip
    )
    return templates