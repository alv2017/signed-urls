def validate_type(value, expected_type: type, field_name: str = "") -> None:
    if not field_name:
        field_name = "Value"
    if not isinstance(value, expected_type):
        raise TypeError(f"{field_name} must be of type {expected_type.__name__}")


def validate_extra_query_parameters(extra_qp: dict) -> None:
    # extra query parameters can not contain reserved keys 'exp' or 'sig'
    if "exp" in extra_qp or "sig" in extra_qp:
        raise ValueError(
            "Extra query parameters cannot contain reserved keys 'exp' or 'sig'."
        )

    # reject non-encodable values in extra query parameters
    allowed_scalars = (str, int, float, bool)
    err_msg = "Extra query parameter contains non-encodable value: {key}: {value}"
    for key, value in extra_qp.items():
        if isinstance(value, allowed_scalars):
            continue
        elif isinstance(value, (list, tuple)):
            if not all(isinstance(item, allowed_scalars) for item in value):
                raise TypeError(err_msg.format(key=key, value=value))
        else:
            raise TypeError(err_msg.format(key=key, value=value))
