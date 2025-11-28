def validate_type(value, expected_type: type, field_name: str = "") -> None:
    if not field_name:
        field_name = "Value"
    if not isinstance(value, expected_type):
        raise TypeError(f"{field_name} must be of type {expected_type.__name__}")
