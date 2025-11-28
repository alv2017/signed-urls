import pytest
from signed_urls import sign_url, verify_signed_url
from signed_urls.utils import supported_algorithms
from tests.data import request_models


@pytest.mark.parametrize("method,url,algorithm", request_models)
def test_sign_verify_url_mtx(method, url, algorithm):
    secret_key = "Test-Secret-Key"
    ttl = 300
    extra_qp = {"keyid": "key001", "nonce": "xR0mP4ab!", "user": "alice"}
    signed_url = sign_url(
        method=method,
        url=url,
        secret_key=secret_key,
        ttl=ttl,
        extra_qp=extra_qp,
        algorithm=algorithm,
    )

    assert verify_signed_url(method=method, signed_url=signed_url, secret_key=secret_key, algorithm=algorithm)


@pytest.mark.parametrize("method,url,algorithm", request_models)
def test_sign_verify_url_no_extra_query_params_mtx(method, url, algorithm):
    secret_key = "Test-Secret-Key"
    ttl = 300
    signed_url = sign_url(
        method=method,
        url=url,
        secret_key=secret_key,
        ttl=ttl,
        algorithm=algorithm,
    )

    assert verify_signed_url(method=method, signed_url=signed_url, secret_key=secret_key, algorithm=algorithm)


@pytest.mark.parametrize("method,url,algorithm", request_models)
def test_sign_verify_url_is_deterministic_mtx(method, url, algorithm):
    secret_key = "Test-Secret-Key"
    ttl = 300
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


@pytest.mark.parametrize("method,url,algorithm", request_models)
@pytest.mark.parametrize("reserved_word", ["exp", "sig"])
def test_sign_verify_url_with_invalid_extra_qp_containing_reserved_words_mtx_exc(method, url, algorithm, reserved_word):
    secret_key = "Test-Secret-Key"
    ttl = 300
    extra_qp = {reserved_word: "some_value", "user": "alice"}
    with pytest.raises(
        ValueError,
        match="Extra query parameters cannot contain reserved keys 'exp' or 'sig'",
    ):
        signed_url = sign_url(
            method=method,
            url=url,
            secret_key=secret_key,
            ttl=ttl,
            extra_qp=extra_qp,
            algorithm=algorithm,
        )


@pytest.mark.parametrize("method,url,algorithm", request_models)
def test_sign_verify_url_expired_mtx_f(method, url, algorithm):
    secret_key = "Test-Secret-Key"
    ttl = -1
    signed_url = sign_url(
        method=method,
        url=url,
        secret_key=secret_key,
        ttl=ttl,
        algorithm=algorithm,
    )

    assert verify_signed_url(
        method=method, signed_url=signed_url, secret_key=secret_key, algorithm=algorithm
    ) is False


@pytest.mark.parametrize("method,url,algorithm", request_models)
def test_sign_verify_url_unsigned_url_mtx_f(method, url, algorithm):
    secret_key = "Test-Secret-Key"
    unsigned_url = url
    assert verify_signed_url(
        method=method, signed_url=unsigned_url, secret_key=secret_key, algorithm=algorithm
    ) is False


@pytest.mark.parametrize("method,url,algorithm", request_models)
def test_sign_verify_url_invalid_key_mtx_f(method, url, algorithm):
    secret_key = "Test-Secret-Key"
    ttl = -1
    signed_url = sign_url(
        method=method,
        url=url,
        secret_key=secret_key,
        ttl=ttl,
        algorithm=algorithm,
    )

    invalid_key = "Invalid"
    assert verify_signed_url(
        method=method, signed_url=signed_url, secret_key=invalid_key, algorithm=algorithm
    ) is False


@pytest.mark.parametrize("method,url,algorithm", request_models)
def test_sing_verify_url_invalid_algorithm_mtx_f(method, url, algorithm):
    secret_key = "Test-Secret-Key"
    ttl = -1
    signed_url = sign_url(
        method=method,
        url=url,
        secret_key=secret_key,
        ttl=ttl,
        algorithm=algorithm,
    )

    invalid_algorithms = [alg for alg in supported_algorithms if alg != algorithm]
    for invalid_algorithm in invalid_algorithms:
        assert verify_signed_url(
            method=method, signed_url=signed_url, secret_key=secret_key, algorithm=invalid_algorithm
        ) is False
