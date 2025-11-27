import base64
import hashlib
import hmac
from urllib.parse import urlencode

supported_algorithms: list[str] = ["SHA256", "SHA512", "BLAKE2B", "BLAKE2S"]


def base64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def base64url_decode(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def create_signature(message: str, secret_key: str, algorithm: str = "SHA256") -> bytes:
    """
    Create an HMAC signature for a message using the provided secret key and algorithm.

    Args:
        message: The message to sign.
        secret_key: The secret key used to compute the HMAC.
        algorithm: Hash algorithm name (one of "SHA256", "SHA512", "BLAKE2B", "BLAKE2S",
                   default: 'SHA256').

    Returns:
        The signature as raw bytes.

    Raises:
        ValueError: If the provided algorithm is not supported.
    """
    if algorithm not in supported_algorithms:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    hmo = hmac.new(
        secret_key.encode(),
        msg=message.encode(),
        digestmod=getattr(hashlib, algorithm.lower()),
    )
    return hmo.digest()


def build_canonical_query_string(params: dict) -> str:
    """
    Build a canonical, URL-encoded query string from the given parameters.

    Keys are sorted lexicographically to ensure stable ordering. If a value is
    a sequence, multiple key/value pairs will be produced for that key.

    Args:
        params: Mapping of query parameter names to values. Values may be a
            single value or a sequence of values.

    Returns:
        URL-encoded query string with keys sorted.
    """
    tmp: dict = {k: params[k] for k in sorted(params.keys())}
    return urlencode(tmp, doseq=True)


def build_canonical_string(
    method: str,
    scheme: str,
    netloc: str,
    path: str,
    params: str | None,
    query: str | None,
    fragment: str | None,
) -> str:
    data = [method.upper(), scheme, netloc, path]
    if params:
        data.append(params)
    if query:
        data.append(query)
    if fragment:
        data.append(fragment)
    return "\n".join(data)
