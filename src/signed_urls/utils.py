import base64
import binascii
import hashlib
import hmac
from collections.abc import Sequence
from typing import TypeAlias
from urllib.parse import urlencode

Scalar: TypeAlias = str | int | float
QueryValue: TypeAlias = Scalar | Sequence[Scalar]
QueryDict: TypeAlias = dict[str, QueryValue]
QueryList: TypeAlias = list[tuple[str, QueryValue]]


supported_algorithms: list[str] = ["SHA256", "SHA512", "BLAKE2B", "BLAKE2S"]


def base64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def base64url_decode(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    try:
        b64_decoded_bytes = base64.urlsafe_b64decode(s + padding)
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"Invalid base64url-encoded string: {str(e)}") from None
    else:
        return b64_decoded_bytes


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
    msg: bytes = message.encode()
    digestmod = getattr(hashlib, algorithm.lower())
    hmo = hmac.new(secret_key.encode(), msg=msg, digestmod=digestmod)
    return hmo.digest()


def build_canonical_query_string(params: QueryDict | QueryList) -> str:
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
    if isinstance(params, dict):
        params = params.items()

    return urlencode(sorted(params), doseq=True)


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
