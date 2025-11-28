import pytest
from signed_urls import sign_url
from tests.data import unsupported_algorithms


def test_sign_url_basic():
    method = "GET"
    url = "https://example.com/resource/123"
    secret_key = "Test-Secret-Key"
    ttl = 300
    extra_qp = {"keyid": "key001", "user": "alice"}
    algorithm = "SHA256"
    signed_url = sign_url(
        method=method,
        url=url,
        secret_key=secret_key,
        ttl=ttl,
        algorithm=algorithm,
        extra_qp=extra_qp,
    )
    assert isinstance(signed_url, str)
    assert "exp=" in signed_url
    assert "sig=" in signed_url
    assert "keyid=key001" in signed_url
    assert "user=alice" in signed_url


def test_sign_url_no_extra_query_params():
    method = "GET"
    url = "https://example.com/resource/123"
    secret_key = "Test-Secret-Key"
    ttl = 300
    algorithm = "SHA256"
    signed_url = sign_url(
        method=method,
        url=url,
        secret_key=secret_key,
        ttl=ttl,
        algorithm=algorithm,
    )

    assert isinstance(signed_url, str)
    assert "exp=" in signed_url
    assert "sig=" in signed_url


def test_sign_url_is_deterministic():
    method = "GET"
    url = "https://example.com/resource/123"
    secret_key = "Test-Secret-Key"
    ttl = 300
    algorithm = "SHA256"
    signed_url_1 = sign_url(
        method=method,
        url=url,
        secret_key=secret_key,
        ttl=ttl,
        algorithm=algorithm,
    )

    signed_url_2 = sign_url(
        method=method,
        url=url,
        secret_key=secret_key,
        ttl=ttl,
        algorithm=algorithm,
    )

    assert signed_url_1 == signed_url_2


def test_sign_url_unicode():
    method = "GET"
    url = "https://example.com/resource?владелец=пользователь"
    secret_key = "Test-Secret-Key"
    ttl = 300
    algorithm = "SHA256"
    signed_url = sign_url(
        method=method,
        url=url,
        secret_key=secret_key,
        ttl=ttl,
        algorithm=algorithm,
    )

    assert isinstance(signed_url, str)
    assert "exp=" in signed_url
    assert "sig=" in signed_url


@pytest.mark.parametrize("algorithm", unsupported_algorithms)
def test_sign_url_with_non_supported_algorithm_exc(algorithm):
    method = "GET"
    url = "https://example.com/resource?user=виталия"
    secret_key = "Test-Secret-Key"
    ttl = 300
    with pytest.raises(ValueError, match=f"Unsupported algorithm: {algorithm}"):
        signed_url = sign_url(
            method=method,
            url=url,
            secret_key=secret_key,
            ttl=ttl,
            algorithm=algorithm,
        )


@pytest.mark.parametrize("reserved_word", ["exp", "sig"])
def test_sign_url_with_invalid_extra_qp_containing_reserved_words_exc(reserved_word):
    method = "GET"
    url = "https://example.com/resource/123"
    secret_key = "Test-Secret-Key"
    ttl = 300
    extra_qp = {reserved_word: "some_value", "user": "alice"}
    algorithm = "SHA256"
    with pytest.raises(
        ValueError,
        match="Extra query parameters cannot contain reserved keys 'exp' or 'sig'",
    ):
        signed_url = sign_url(
            method=method,
            url=url,
            secret_key=secret_key,
            ttl=ttl,
            algorithm=algorithm,
            extra_qp=extra_qp,
        )


def test_sign_url_when_url_empty_exc():
    method = "GET"
    url = ""
    secret_key = "Test-Secret-Key"
    ttl = 300
    algorithm = "SHA256"
    with pytest.raises(ValueError, match="URL cannot be empty"):
        signed_url = sign_url(
            method=method,
            url=url,
            secret_key=secret_key,
            ttl=ttl,
            algorithm=algorithm,
        )


def test_sign_url_bytes_secret_key_exc():
    method = "GET"
    url = "https://example.com/resource/123"
    secret_key = b"Test-Secret-Key"
    ttl = 300
    algorithm = "SHA256"
    with pytest.raises(TypeError, match="Secret key must be a string"):
        signed_url = sign_url(
            method=method,
            url=url,
            secret_key=secret_key,
            ttl=ttl,
            algorithm=algorithm,
        )
