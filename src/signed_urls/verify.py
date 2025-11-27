import hmac
import time
from urllib.parse import parse_qs, urlencode, urlparse

from utils import base64url_decode, build_canonical_string, create_signature


def verify_signed_url(
    method: str, signed_url: str, secret_key: str, algorithm="SHA256"
) -> bool:
    """
    Verify a signed URL.

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
    # Parse the signed URL
    parsed = urlparse(signed_url)
    query_params = parse_qs(parsed.query)

    # Extract the signature from the query parameters
    signature_b64 = query_params.pop("sig", [None])[0]
    if not signature_b64:
        return False
    else:
        signature: bytes = base64url_decode(signature_b64)

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

    # Generate a new signature using the secret key
    expected_signature = create_signature(
        message_to_sign, secret_key, algorithm=algorithm
    )

    # Compare the provided signature with the expected signature
    return hmac.compare_digest(signature, expected_signature)
