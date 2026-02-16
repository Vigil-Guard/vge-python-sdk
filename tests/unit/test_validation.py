"""Unit tests for strict-mode validation helpers."""

from __future__ import annotations

from typing import List, Optional

import pytest
from pydantic import BaseModel, ConfigDict, Field

from vigil.types._validation import validate_no_extra_fields


class Inner(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    name: str = Field(alias="name")
    value: int = Field(alias="value")


class Outer(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    title: str = Field(alias="title")
    inner: Inner = Field(alias="inner")
    items: Optional[List[Inner]] = Field(default=None, alias="items")


class AliasedModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    user_name: str = Field(alias="userName")
    email_address: str = Field(alias="emailAddress")


class TestValidateNoExtraFields:
    def test_valid_data_passes(self) -> None:
        data = {"title": "Test", "inner": {"name": "x", "value": 1}}
        validate_no_extra_fields(Outer, data)

    def test_extra_field_at_root_raises(self) -> None:
        data = {"title": "Test", "inner": {"name": "x", "value": 1}, "unknown": True}
        with pytest.raises(ValueError, match="Unexpected fields at Outer: unknown"):
            validate_no_extra_fields(Outer, data)

    def test_extra_field_in_nested_model_raises(self) -> None:
        data = {"title": "Test", "inner": {"name": "x", "value": 1, "extra": "bad"}}
        with pytest.raises(ValueError, match="Unexpected fields at inner: extra"):
            validate_no_extra_fields(Outer, data)

    def test_extra_field_in_list_items_raises(self) -> None:
        data = {
            "title": "Test",
            "inner": {"name": "x", "value": 1},
            "items": [{"name": "a", "value": 2, "rogue": 99}],
        }
        with pytest.raises(ValueError, match=r"Unexpected fields at items\[0\]: rogue"):
            validate_no_extra_fields(Outer, data)

    def test_non_dict_input_returns_silently(self) -> None:
        validate_no_extra_fields(Outer, "not a dict")
        validate_no_extra_fields(Outer, 42)
        validate_no_extra_fields(Outer, None)

    def test_alias_and_field_name_both_accepted(self) -> None:
        validate_no_extra_fields(AliasedModel, {"userName": "alice", "emailAddress": "a@b.c"})
        validate_no_extra_fields(AliasedModel, {"user_name": "alice", "email_address": "a@b.c"})

    def test_multiple_extra_fields_sorted(self) -> None:
        data = {"title": "T", "inner": {"name": "x", "value": 1}, "zzz": 1, "aaa": 2}
        with pytest.raises(ValueError, match="aaa, zzz"):
            validate_no_extra_fields(Outer, data)

    def test_none_nested_value_skipped(self) -> None:
        data = {"title": "Test", "inner": {"name": "x", "value": 1}, "items": None}
        validate_no_extra_fields(Outer, data)

    def test_custom_path_prefix(self) -> None:
        data = {"name": "x", "value": 1, "extra": True}
        with pytest.raises(ValueError, match="Unexpected fields at root.inner: extra"):
            validate_no_extra_fields(Inner, data, path="root.inner")
