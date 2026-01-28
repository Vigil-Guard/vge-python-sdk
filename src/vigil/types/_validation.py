"""
Internal response validation helpers.
"""

from __future__ import annotations

from typing import Any, get_args, get_origin

from pydantic import BaseModel


def validate_no_extra_fields(model: type[BaseModel], data: Any, path: str = "") -> None:
    """Ensure response data contains no unknown fields for the given model."""
    if not isinstance(data, dict):
        return

    allowed = _allowed_keys(model)
    extra_keys = sorted(key for key in data if key not in allowed)
    if extra_keys:
        location = path or model.__name__
        extras = ", ".join(extra_keys)
        raise ValueError(f"Unexpected fields at {location}: {extras}")

    for field_name, field in model.model_fields.items():
        key = field.alias or field_name
        if key in data:
            value = data[key]
        elif field_name in data:
            value = data[field_name]
        else:
            continue
        _validate_value(field.annotation, value, f"{path}.{key}" if path else key)


def _allowed_keys(model: type[BaseModel]) -> set[str]:
    allowed: set[str] = set()
    for name, field in model.model_fields.items():
        allowed.add(name)
        if field.alias:
            allowed.add(field.alias)
    return allowed


def _validate_value(annotation: Any, value: Any, path: str) -> None:
    if value is None:
        return

    if _is_model_type(annotation):
        if isinstance(value, dict):
            validate_no_extra_fields(annotation, value, path)
        return

    origin = get_origin(annotation)
    args = get_args(annotation)

    if origin in (list, tuple):
        if not isinstance(value, list):
            return
        elem_type = args[0] if args else None
        for idx, item in enumerate(value):
            _validate_value(elem_type, item, f"{path}[{idx}]")
        return

    if origin is None:
        return

    if origin is not None and args:
        for arg in args:
            _validate_value(arg, value, path)


def _is_model_type(annotation: Any) -> bool:
    try:
        return isinstance(annotation, type) and issubclass(annotation, BaseModel)
    except TypeError:
        return False
