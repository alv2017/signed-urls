import time
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from signed_urls.utils import (
    QueryDict,
    QueryList,
    base64url_encode,
    build_canonical_query_string,
    build_canonical_string,
    create_signature,
    supported_algorithms,
)
from signed_urls.validators import validate_extra_query_parameters, validate_type


def sign_url(
    method: str,
    url: str,
    secret_key: str,
    ttl: int,
    algorithm: str = "SHA256",
    extra_qp: QueryDict | None = None,
) -> str:
    """
    Sign a URL by adding an expiration timestamp and a signature.

    Builds a canonical string from the request components, computes a
    HMAC-based signature using `secret_key` and `algorithm`, and returns the
    URL with `exp` and `sig` query parameters appended.

    Note:
    This function does NOT perform semantic URL validation.
    Any non-empty string that can be parsed by urllib.parse.urlparse
    will be signed. URL correctness is the caller's responsibility.

    Args:
        method (str): HTTP method (e.g. 'GET', 'POST').
        url (str): The URL to sign.
        secret_key (str): Secret key used to create the signature.
        ttl (int): Time-to-live in seconds; expiration is current time + ttl.
        extra_qp (dict | None): Additional query parameters to include in the
            signature and final URL.
        algorithm (str): Hash algorithm used for the signature (default: \'SHA256\').

    Returns:
        str: The signed URL containing `exp` and `sig` query parameters.
    """
    # Validate http method
    validate_type(value=method, expected_type=str, field_name="HTTP method")

    # Validate url
    validate_type(value=url, expected_type=str, field_name="URL")
    if len(url.strip()) == 0:
        raise ValueError("URL cannot be empty")

    # Validate secret key
    validate_type(value=secret_key, expected_type=str, field_name="Secret key")

    # Validate ttl
    validate_type(value=ttl, expected_type=int, field_name="TTL")

    # Validate algorithm
    validate_type(value=algorithm, expected_type=str, field_name="Algorithm")
    if algorithm not in supported_algorithms:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    # Validate extra_qp: extra query parameters
    if extra_qp is not None:
        validate_type(
            value=extra_qp, expected_type=dict, field_name="Extra query parameters"
        )
        validate_extra_query_parameters(extra_qp)

    expire_ts = int(time.time()) + ttl
    parsed = urlparse(url)

    query = parsed.query
    query_params = parse_qs(query)
    query_params["exp"] = [str(expire_ts)]
    query_params.update(extra_qp or {})

    sorted_query_params: QueryList = sorted(query_params.items())

    canonical_query_string = build_canonical_query_string(sorted_query_params)

    scheme = parsed.scheme
    netloc = parsed.netloc
    path = parsed.path
    params = parsed.params
    fragment = parsed.fragment

    message_to_sign = build_canonical_string(
        method, scheme, netloc, path, params, canonical_query_string, fragment
    )

    signature: bytes = create_signature(message_to_sign, secret_key, algorithm)
    signature_b64 = base64url_encode(signature)
    sorted_query_params.append(("sig", [signature_b64]))

    return urlunparse(
        (
            scheme,
            netloc,
            path,
            params,
            urlencode(sorted_query_params, doseq=True),
            fragment,
        )
    )
