from urllib.parse import parse_qs, urlencode, urlparse

import pytest

from signed_urls.sign import sign_url
from tests.data import (
    request_methods,
    request_models,
    secret_key,
    supported_algorithms,
)

test_secret_key = secret_key
test_ttl = 300

methods_to_test = request_methods

# urls_to_test = [
#     "http://example.com",
#     "https://example.com/path/to/resource",
#     "https://example.com/path?foo=bar&baz=qux",
#     "https://example.com/path?foo=bar#section2",
#     "https://example.com/path?foo=1&foo=2&foo=3&baz=qux",
# ]

non_encodable_extra_qp = [
    {"x": {"a": "1", "b": "2"}},
    {"x": {1, 2, 3}},
    {"x": [b"bytes1", b"bytes2"]},
    {"x": object()},
    {"x": None},
    {"x": lambda y: y},
]

# 1. Basic Functionality


@pytest.mark.parametrize("method,url,algorithm", request_models)
def test_sign_url_returns_string(method, url, algorithm):
    signed_url = sign_url(
        method=method,
        url=url,
        secret_key=test_secret_key,
        ttl=test_ttl,
        algorithm=algorithm,
    )
    assert isinstance(signed_url, str)


@pytest.mark.parametrize("method,url,algorithm", request_models)
def test_sign_url_with_extra_query_parameters_returns_string(method, url, algorithm):
    signed_url = sign_url(
        method=method,
        url=url,
        secret_key=test_secret_key,
        ttl=test_ttl,
        algorithm=algorithm,
        extra_qp={"keyid": "key001", "user": "alice"},
    )
    assert isinstance(signed_url, str)


@pytest.mark.parametrize("method,url,algorithm", request_models)
def test_sign_url_preserves_original_url_data(method, url, algorithm):
    signed_url = sign_url(
        method=method,
        url=url,
        secret_key=test_secret_key,
        ttl=test_ttl,
        algorithm=algorithm,
    )
    url_data = urlparse(url)
    url_query_params = parse_qs(url_data.query)
    signed_url_data = urlparse(signed_url)
    signed_query_params = parse_qs(signed_url_data.query)

    # signed url preserves the original url data
    assert url_data.scheme == signed_url_data.scheme
    assert url_data.netloc == signed_url_data.netloc
    assert url_data.path == signed_url_data.path
    assert url_data.fragment == signed_url_data.fragment

    # signed url preserves the original query parameters
    for k, v in url_query_params.items():
        assert k in signed_query_params
        assert signed_query_params[k] == v


@pytest.mark.parametrize("method,url,algorithm", request_models)
def test_sign_url_with_extra_query_parameters_preserves_original_url_data(
    method, url, algorithm
):
    signed_url = sign_url(
        method=method,
        url=url,
        secret_key=test_secret_key,
        ttl=test_ttl,
        algorithm=algorithm,
        extra_qp={"keyid": "key001", "user": "alice"},
    )
    url_data = urlparse(url)
    url_query_params = parse_qs(url_data.query)
    signed_url_data = urlparse(signed_url)
    signed_query_params = parse_qs(signed_url_data.query)

    # signed url preserves the original url data
    assert url_data.scheme == signed_url_data.scheme
    assert url_data.netloc == signed_url_data.netloc
    assert url_data.path == signed_url_data.path
    assert url_data.fragment == signed_url_data.fragment

    # signed url preserves the original query parameters
    for k, v in url_query_params.items():
        assert k in signed_query_params
        assert signed_query_params[k] == v


@pytest.mark.parametrize("method,url,algorithm", request_models)
def test_sign_url_contains_exp_and_sig(method, url, algorithm):
    signed_url = sign_url(
        method=method,
        url=url,
        secret_key=test_secret_key,
        ttl=test_ttl,
        algorithm=algorithm,
    )
    signed_url_data = urlparse(signed_url)
    signed_query_params = parse_qs(signed_url_data.query)
    expire_ts = signed_query_params["exp"][0]

    assert "exp" in signed_query_params
    assert "sig" in signed_query_params

    # successful conversion to int
    assert expire_ts.isdigit()


@pytest.mark.parametrize("method,url,algorithm", request_models)
def test_sign_url_with_extra_query_parameters_contains_extra_qp_exp_and_sig(
    method, url, algorithm
):
    extra_qp = {
        "keyid": "key001",
        "user": "alice",
        "chapter": [1, 2],
        "job": "тест",
        "id": 1,
    }
    signed_url = sign_url(
        method=method,
        url=url,
        secret_key=test_secret_key,
        ttl=test_ttl,
        algorithm=algorithm,
        extra_qp=extra_qp,
    )
    signed_url_data = urlparse(signed_url)
    signed_query_params = parse_qs(signed_url_data.query)

    extra_qp_normalized = parse_qs(urlencode(extra_qp, doseq=True))

    # 'exp' and 'sig' are present
    assert "exp" in signed_query_params
    assert "sig" in signed_query_params

    # extra query parameters are present
    for k, v in extra_qp_normalized.items():
        assert k in signed_query_params
        assert signed_query_params[k] == v

    # successful conversion to int
    try:
        int(signed_query_params["exp"][0])
    except ValueError:
        pytest.fail("exp parameter is not a valid integer timestamp")


# 2. The signing process is deterministic


@pytest.mark.parametrize("method,url,algorithm", request_models)
def test_sign_url_is_deterministic(method, url, algorithm):
    signed_url_1 = sign_url(
        method=method,
        url=url,
        secret_key=test_secret_key,
        ttl=test_ttl,
        algorithm=algorithm,
    )
    signed_url_2 = sign_url(
        method=method,
        url=url,
        secret_key=test_secret_key,
        ttl=test_ttl,
        algorithm=algorithm,
    )
    exp_1 = parse_qs(urlparse(signed_url_1).query)["exp"][0]
    exp_2 = parse_qs(urlparse(signed_url_2).query)["exp"][0]
    if exp_1 == exp_2:
        assert signed_url_1 == signed_url_2


# 3.  Exceptions


@pytest.mark.parametrize("method", request_methods)
@pytest.mark.parametrize("algorithm", supported_algorithms)
def test_sign_url_when_url_is_empty_raises_value_error(method, algorithm):
    with pytest.raises(ValueError, match="URL cannot be empty"):
        sign_url(
            method=method,
            url="",
            secret_key=test_secret_key,
            ttl=test_ttl,
            algorithm=algorithm,
        )


@pytest.mark.parametrize("method,url,algorithm", request_models)
@pytest.mark.parametrize("reserved_keyword", ["exp", "sig"])
def test_sign_url_when_extra_qp_contains_exp_raises_value_error(
    method, url, algorithm, reserved_keyword
):
    with pytest.raises(
        ValueError,
        match="Extra query parameters cannot contain reserved keys 'exp' or 'sig'.",
    ):
        sign_url(
            method=method,
            url=url,
            secret_key=test_secret_key,
            ttl=test_ttl,
            algorithm=algorithm,
            extra_qp={reserved_keyword: "some_value", "user": "alice"},
        )


@pytest.mark.parametrize("method,url,algorithm", request_models)
@pytest.mark.parametrize("non_encodable_extra_qp", non_encodable_extra_qp)
def test_sign_url_with_non_encodable_extra_qp_raises_type_error(
    method, url, algorithm, non_encodable_extra_qp
):
    with pytest.raises(TypeError) as exc_info:
        sign_url(
            method=method,
            url=url,
            secret_key=test_secret_key,
            ttl=test_ttl,
            algorithm=algorithm,
            extra_qp=non_encodable_extra_qp,
        )
    assert "Extra query parameter contains non-encodable value" in str(exc_info.value)
