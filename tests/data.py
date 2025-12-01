from signed_urls.utils import supported_algorithms

secret_key = "Test-Secret-Key"

request_methods = [
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "PATCH",
]

algorithms = supported_algorithms

unsupported_algorithms = ["MD5", "SHA1", "SHA224", "SHA3_256", "SM3"]

non_encodable_extra_qp = [
    {"x": {"a": "1", "b": "2"}},
    {"x": {1, 2, 3}},
    {"x": [b"bytes1", b"bytes2"]},
    {"x": object()},
    {"x": None},
    {"x": lambda y: y},
]

test_urls = [
    # Simple HTTP URL, no query
    "http://example.com",
    # HTTPS URL with path
    "https://example.com/path/to/resource",
    # URL with existing query parameters
    "https://example.com/path?foo=bar&baz=qux",
    # URL with fragment
    "https://example.com/path#section1",
    # URL with query and fragment
    "https://example.com/path?foo=bar#section2",
    # URL with multiple query values for the same key
    "https://example.com/path?foo=1&foo=2&foo=3",
    # URL with special characters in path and query
    "https://example.com/çöödé?param1=äöü&param2=100%",
    # URL with port number
    "http://example.com:8080/path",
    # URL with IP address
    "http://127.0.0.1/resource?debug=true",
    # URL with trailing slash
    "https://example.com/path/",
    # URL with empty query
    "https://example.com/path?",
    # URL with user info (username:password)
    "https://user:pass@example.com/path?x=1",
]

request_models = [
    (method, url, algorithm)
    for method in request_methods
    for url in test_urls
    for algorithm in algorithms
]
