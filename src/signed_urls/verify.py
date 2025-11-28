import hmac
import re
import time
from urllib.parse import parse_qs, urlencode, urlparse

from signed_urls.utils import (
    base64url_decode,
    build_canonical_string,
    create_signature,
    supported_algorithms,
)
from signed_urls.validators import validate_type

BASE64URL_REGEX = re.compile(r"^[A-Za-z0-9_-]+$")


def verify_signed_url(
    method: str, signed_url: str, secret_key: str, algorithm="SHA256"
) -> bool:
    """
    Verify a signed URL.

    Note:
    This function does NOT perform semantic URL validation.
    Any non-empty string that can be parsed by urllib.parse.urlparse
    will be verified. URL correctness is the caller's responsibility.

    Args:
        method (str): HTTP method used to sign the request (e.g., 'GET').
        signed_url (str): The full URL containing the signature query parameter 'sig'.
        secret_key (str): Secret key used to create the HMAC signature.
        algorithm (str): Hash algorithm name passed to the signing helper
                         (default: 'SHA256').

    Returns:
        bool: True if the signature in the URL matches the expected signature computed
        from the canonicalized request and provided secret_key; False otherwise.
    """
    # Validate http method
    validate_type(value=method, expected_type=str, field_name="HTTP method")
    # Validate signed_url
    validate_type(value=signed_url, expected_type=str, field_name="Signed URL")
    if len(signed_url.strip()) == 0:
        raise ValueError("Signed URL cannot be empty")
    # Validate secret key
    validate_type(value=secret_key, expected_type=str, field_name="Secret key")
    # Validate algorithm
    validate_type(value=algorithm, expected_type=str, field_name="Algorithm")
    if algorithm not in supported_algorithms:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    # Parse the signed URL
    parsed = urlparse(signed_url)
    query_params = parse_qs(parsed.query)

    # Extract the signature from the query parameters
    signature_b64 = query_params.pop("sig", [None])[0]

    # Signature must be present
    if not signature_b64:
        return False

    # Validate signature length (base64url-encoded HMAC signatures)
    if len(signature_b64) < 43 or len(signature_b64) > 86:
        return False

    # Validate the signature format
    if not BASE64URL_REGEX.match(signature_b64):
        return False

    try:
        signature: bytes = base64url_decode(signature_b64)
    except ValueError:
        return False

    # Extract expiry timestamp
    exp = query_params.get("exp", [None])[0]
    if not exp:
        return False
    if int(exp) < int(time.time()):
        return False

    # Reconstruct the message to sign
    unsigned_query = urlencode(query_params, doseq=True)
    message_to_sign = build_canonical_string(
        method,
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        unsigned_query,
        parsed.fragment,
    )

    # Generate an expected signature using the secret key
    expected_signature = create_signature(
        message_to_sign, secret_key, algorithm=algorithm
    )

    # Compare the signature from the url with the expected signature
    return hmac.compare_digest(signature, expected_signature)
