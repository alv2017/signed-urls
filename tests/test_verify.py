import pytest
from signed_urls.sign import sign_url
from signed_urls.verify import verify_signed_url
from signed_urls.utils import supported_algorithms
from tests.data import request_methods, unsupported_algorithms


test_url = "https://example.com/resource/123?access=read&owner=microsoft"
test_url_with_invalid_signature = test_url + "&sig=InvalidSignature"

request_method = "GET"
secret_key = "Test-Secret-Key"
ttl = 300
algorithm = "SHA256"

wrong_algorithms = [alg for alg in supported_algorithms if alg != algorithm]
tampered_methods = [m for m in request_methods if m != request_method]


signed_test_url = sign_url(
    method=request_method,
    url=test_url,
    secret_key=secret_key,
    ttl=ttl,
    algorithm=algorithm,
)

signed_test_url_with_extra_qp = sign_url(
    method=request_method,
    url=test_url,
    secret_key=secret_key,
    ttl=ttl,
    algorithm=algorithm,
    extra_qp={"keyid": "key001", "user": "alice"},
)

expired_signed_test_url = sign_url(
    method=request_method,
    url=test_url,
    secret_key=secret_key,
    ttl=-1,
    algorithm=algorithm,
)


@pytest.mark.parametrize("signed_url", [signed_test_url, signed_test_url_with_extra_qp])
def test_verify_url_valid_signature(signed_url):
    assert verify_signed_url(
        method=request_method,
        signed_url=signed_url,
        secret_key=secret_key,
        algorithm=algorithm,
    )


@pytest.mark.parametrize("algorithm", unsupported_algorithms)
def test_verify_url_unsupported_algorithm_exc(algorithm):
    with pytest.raises(ValueError, match=f"Unsupported algorithm: {algorithm}"):
        verify_signed_url(
            method=request_method,
            signed_url=signed_test_url,
            secret_key=secret_key,
            algorithm=algorithm,
        )


@pytest.mark.parametrize("tampered_method", tampered_methods)
def test_verify_url_tampered_method_f(tampered_method):
    tampered_method = "POST"
    assert verify_signed_url(
        method=tampered_method,
        signed_url=signed_test_url,
        secret_key=secret_key,
        algorithm=algorithm,
    ) is False


def test_verify_url_tampered_query_param_f():
    tempered_url = signed_test_url.replace("access=read", "access=write")
    assert verify_signed_url(
        method=request_method,
        signed_url=tempered_url,
        secret_key=secret_key,
        algorithm=algorithm,
    ) is False


def test_verify_url_invalid_signature_f():
    assert verify_signed_url(
        method=request_method,
        signed_url=test_url_with_invalid_signature,
        secret_key=secret_key,
        algorithm=algorithm,
    ) is False


def test_verify_url_expired_signature_f():
    assert verify_signed_url(
        method=request_method,
        signed_url=expired_signed_test_url,
        secret_key=secret_key,
        algorithm=algorithm,
    ) is False


def test_verify_url_unsigned_f():
    assert verify_signed_url(
        method=request_method,
        signed_url=test_url,
        secret_key=secret_key,
        algorithm=algorithm,
    ) is False


def test_verify_url_wrong_key_f():
    wrong_secret_key = secret_key + "_wrong"
    assert verify_signed_url(
        method=request_method,
        signed_url=test_url,
        secret_key=wrong_secret_key,
        algorithm=algorithm,
    ) is False


@pytest.mark.parametrize("algorithm", wrong_algorithms)
def test_verify_url_wrong_algorithm_f(algorithm):
    assert verify_signed_url(
        method=request_method,
        signed_url=test_url,
        secret_key=secret_key,
        algorithm=algorithm,
    ) is False
