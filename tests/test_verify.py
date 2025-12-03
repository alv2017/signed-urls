from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import pytest

from signed_urls import sign_url, verify_signed_url
from signed_urls.utils import supported_algorithms
from tests.data import (
    request_methods,
    secret_key,
    unsupported_algorithms,
)

method = "GET"
test_secret_key = secret_key
algorithm = "SHA256"

test_url = "https://example.com/resource/123?access=read&owner=microsoft"
test_url_with_invalid_signature = "https://example.com/resource/123?access=read&owner=microsoft&exp=1234567890&sig=FakeSignature"
test_url_with_missing_signature = (
    "https://example.com/resource/123?access=read&owner=microsoft&exp=9999999999"
)

test_signed_url = sign_url(
    method=method,
    url=test_url,
    secret_key=secret_key,
    ttl=300,
    algorithm=algorithm,
)

test_expired_signed_url = sign_url(
    method=method,
    url=test_url,
    secret_key=secret_key,
    ttl=-1,
    algorithm=algorithm,
)


# 1. Basic Functionality


def test_verify_signed_url():
    """
    Test: valid signed URL is verified successfully

    Given: a valid request method, url, secret_key, and algorithm
    Then: verify_signed_url should return True
    """
    assert verify_signed_url(
        method=method,
        signed_url=test_signed_url,
        secret_key=test_secret_key,
        algorithm=algorithm,
    )


def test_verify_signed_url_with_fake_signature_returns_false():
    """
    Test: verify_signed_url returns False when signature is invalid

    Given: a signed URL with an invalid signature
    Then: verify_signed_url should return False
    """
    assert not verify_signed_url(
        method=method,
        signed_url=test_url_with_invalid_signature,
        secret_key=test_secret_key,
        algorithm=algorithm,
    )


def test_verify_signed_url_when_url_is_expired_returns_false():
    """
    Test: verify_signed_url returns False when URL is expired

    Given: a signed URL that has expired
    Then: verify_signed_url should return False
    """
    assert not verify_signed_url(
        method=method,
        signed_url=test_expired_signed_url,
        secret_key=test_secret_key,
        algorithm=algorithm,
    )


def test_verify_signed_url_with_invalid_method_returns_false():
    """
    Test: verify_signed_url returns False when method is tampered

    Given: a signed URL with a tampered method
    Then: verify_signed_url should return False
    """
    tampered_methods = [m for m in request_methods if m != method]

    for tm in tampered_methods:
        assert not verify_signed_url(
            method=tm,
            signed_url=test_signed_url,
            secret_key=test_secret_key,
            algorithm=algorithm,
        )


def test_verify_signed_url_with_tampered_path_returns_false():
    """
    Test: verify_signed_url returns False when path is tampered

    Given: a signed URL with a tampered path
    Then: verify_signed_url should return False
    """
    signed_url = test_signed_url

    parsed = urlparse(signed_url)
    tampered_path = "/tampered_resource"
    tampered_url = urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            tampered_path,
            parsed.params,
            parsed.query,
            parsed.fragment,
        )
    )

    assert not verify_signed_url(
        method=method,
        signed_url=tampered_url,
        secret_key=test_secret_key,
        algorithm=algorithm,
    )


def test_verify_signed_url_with_modified_query_parameters_returns_false():
    signed_url = test_signed_url

    parsed = urlparse(signed_url)
    qp = parse_qs(parsed.query)
    qp["access"] = ["write"]  # Modify existing query parameter
    modified_query_string = urlencode(sorted(qp.items()), doseq=True)

    modified_url = urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            modified_query_string,
            parsed.fragment,
        )
    )
    assert not verify_signed_url(
        method=method,
        signed_url=modified_url,
        secret_key=test_secret_key,
        algorithm=algorithm,
    )


def test_verify_signed_url_use_with_wrong_secret_key_returns_false():
    """
    Test: verify_signed_url returns False when wrong secret key is used

    Given: a signed URL and a wrong secret key
    Then: verify_signed_url should return False
    """
    signed_url = test_signed_url

    wrong_secret_key = "Wrong-Secret-Key"

    assert not verify_signed_url(
        method=method,
        signed_url=signed_url,
        secret_key=wrong_secret_key,
        algorithm=algorithm,
    )


def test_sing_verify_url_wrong_algorithm_returns_false():
    """
    Test: verify_signed_url returns False when invalid algorithm is used

    Given: a signed URL and an invalid algorithm
    Then: verify_signed_url should return False
    """
    signed_url = test_signed_url

    wrong_algorithms = [alg for alg in supported_algorithms if alg != algorithm]
    for wrong_algorithm in wrong_algorithms:
        assert (
            verify_signed_url(
                method=method,
                signed_url=signed_url,
                secret_key=secret_key,
                algorithm=wrong_algorithm,
            )
            is False
        )


# 3. Exceptions


@pytest.mark.parametrize("unsupported_algorithm", unsupported_algorithms)
def test_verify_signed_url_unsupported_algorithm_raises_value_error(
    unsupported_algorithm,
):
    """
    Test: verify_signed_url raises ValueError for unsupported algorithm

    Given: an unsupported algorithm
    Then: verify_signed_url should raise ValueError
    """
    with pytest.raises(
        ValueError, match=f"Unsupported algorithm: {unsupported_algorithms}"
    ):
        verify_signed_url(
            method=method,
            signed_url=test_signed_url,
            secret_key=test_secret_key,
            algorithm=unsupported_algorithm,
        )


def test_signed_url_passed_as_empty_string_raises_value_error():
    """
    Test: verify_signed_url raises ValueError when signed_url is empty string

    Given: an empty signed_url
    Then: verify_signed_url should raise ValueError
    """
    with pytest.raises(ValueError, match="URL cannot be empty"):
        verify_signed_url(
            method=method,
            signed_url="",
            secret_key=test_secret_key,
            algorithm=algorithm,
        )


def test_verify_signed_url_when_exp_is_missing_raises_value_error():
    """
    Test: verify_signed_url returns False when exp is missing

    Given: a signed URL without an exp parameter
    Then: verify_signed_url should raise ValueError
    """
    signed_url = test_signed_url

    parsed = urlparse(signed_url)
    qp = parse_qs(parsed.query)
    qp.pop("exp", None)
    parsed_query = urlencode(sorted(qp.items()), doseq=True)

    signed_url_without_exp = urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            parsed_query,
            parsed.fragment,
        )
    )

    # signed url without exp should raise ValueError
    with pytest.raises(ValueError, match="Invalid signed url: missing 'exp' parameter"):
        assert not verify_signed_url(
            method=method,
            signed_url=signed_url_without_exp,
            secret_key=test_secret_key,
            algorithm=algorithm,
        )


def test_verify_signed_url_when_signature_is_missing_raises_value_error():
    """
    Test: verify_signed_url raises ValueError when signature is missing

    Given: a signed URL without a signature
    Then: verify_signed_url should return False
    """
    with pytest.raises(ValueError, match="Invalid signed url: missing 'sig' parameter"):
        assert not verify_signed_url(
            method=method,
            signed_url=test_url_with_missing_signature,
            secret_key=test_secret_key,
            algorithm=algorithm,
        )
