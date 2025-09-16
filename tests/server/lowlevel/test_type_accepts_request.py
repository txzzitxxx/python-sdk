"""Unit tests for the type_accepts_request function."""

from typing import Any, TypeVar

import pytest

from mcp.server.lowlevel.func_inspection import type_accepts_request
from mcp.types import ListPromptsRequest, ListResourcesRequest, ListToolsRequest


@pytest.mark.parametrize(
    "param_type,request_type,expected,description",
    [
        # Exact type matches
        (ListPromptsRequest, ListPromptsRequest, True, "exact type match"),
        (ListToolsRequest, ListPromptsRequest, False, "different request type"),
        (str, ListPromptsRequest, False, "string type"),
        (int, ListPromptsRequest, False, "int type"),
        (None, ListPromptsRequest, False, "None type"),
        # Any type
        (Any, ListPromptsRequest, True, "Any type accepts all"),
        # Union types with request type
        (ListPromptsRequest | None, ListPromptsRequest, True, "Optional request type"),
        (str | ListPromptsRequest, ListPromptsRequest, True, "Union with request type (request second)"),
        (ListPromptsRequest | str, ListPromptsRequest, True, "Union with request type (request first)"),
        (
            ListPromptsRequest | ListToolsRequest,
            ListPromptsRequest,
            True,
            "Union of multiple request types",
        ),
        # Union types without request type
        (str | int, ListPromptsRequest, False, "Union of primitives"),
        (
            ListToolsRequest | ListResourcesRequest,
            ListPromptsRequest,
            False,
            "Union of different request types",
        ),
        (str | None, ListPromptsRequest, False, "Optional string"),
        # Nested unions
        (
            ListPromptsRequest | str | int,
            ListPromptsRequest,
            True,
            "nested Union with request type",
        ),
        (str | int | bool, ListPromptsRequest, False, "nested Union without request type"),
        # Generic types
        (list[str], ListPromptsRequest, False, "generic list type"),
        (list[ListPromptsRequest], ListPromptsRequest, False, "list of requests"),
    ],
)
def test_type_accepts_request_simple(
    param_type: Any,
    request_type: type,
    expected: bool,
    description: str,
) -> None:
    """Test type_accepts_request with simple type combinations."""
    assert type_accepts_request(param_type, request_type) is expected, f"Failed: {description}"


@pytest.mark.parametrize(
    "typevar_factory,expected,description",
    [
        # TypeVar with bounds
        (lambda: TypeVar("BoundRequest", bound=ListPromptsRequest), True, "TypeVar bound to request type"),
        (lambda: TypeVar("BoundString", bound=str), False, "TypeVar bound to different type"),
        # TypeVar with constraints
        (
            lambda: TypeVar("ConstrainedRequest", ListPromptsRequest, ListToolsRequest),
            True,
            "TypeVar constrained to include request type",
        ),
        (lambda: TypeVar("ConstrainedPrimitives", str, int), False, "TypeVar constrained to primitives"),
        # TypeVar without bounds or constraints
        (lambda: TypeVar("T"), False, "unbounded TypeVar"),
    ],
)
def test_type_accepts_request_typevar(
    typevar_factory: Any,
    expected: bool,
    description: str,
) -> None:
    """Test type_accepts_request with TypeVar types."""
    param_type = typevar_factory()
    assert type_accepts_request(param_type, ListPromptsRequest) is expected, f"Failed: {description}"
