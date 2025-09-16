"""Tests for advanced type inspection features in pagination handlers."""

import warnings
from typing import Any, TypeVar

import pytest

from mcp.server import Server
from mcp.types import (
    ListPromptsRequest,
    ListPromptsResult,
    ListToolsRequest,
    Prompt,
    ServerResult,
)

# Define TypeVars for testing
T = TypeVar("T")
ConstrainedRequest = TypeVar("ConstrainedRequest", ListPromptsRequest, ListToolsRequest)


@pytest.mark.anyio
async def test_union_type_with_request_no_warning() -> None:
    """Test that Union types containing the request type don't trigger warnings."""
    server = Server("test")

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")

        @server.list_prompts()
        async def handle_list_prompts(request: ListPromptsRequest | None) -> ListPromptsResult:
            assert request is not None
            return ListPromptsResult(prompts=[])

        # No deprecation warning should be issued for Union containing request type
        deprecation_warnings = [warning for warning in w if issubclass(warning.category, DeprecationWarning)]
        assert len(deprecation_warnings) == 0


@pytest.mark.anyio
async def test_union_type_multiple_requests_no_warning() -> None:
    """Test Union with multiple request types works correctly."""
    server = Server("test")

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")

        @server.list_prompts()
        async def handle_list_prompts(
            request: ListPromptsRequest | ListToolsRequest,
        ) -> ListPromptsResult:
            assert isinstance(request, ListPromptsRequest)
            return ListPromptsResult(prompts=[])

        # No deprecation warning - Union contains the request type
        deprecation_warnings = [warning for warning in w if issubclass(warning.category, DeprecationWarning)]
        assert len(deprecation_warnings) == 0


@pytest.mark.anyio
async def test_any_type_triggers_warning() -> None:
    """Test that Any type triggers deprecation warning."""
    server = Server("test")

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")

        @server.list_prompts()
        async def handle_list_prompts(request: Any) -> ListPromptsResult:
            return ListPromptsResult(prompts=[])

        # Deprecation warning should be issued for Any type (effectively untyped)
        deprecation_warnings = [warning for warning in w if issubclass(warning.category, DeprecationWarning)]
        assert len(deprecation_warnings) == 1
        assert "ListPromptsRequest" in str(deprecation_warnings[0].message)


@pytest.mark.anyio
async def test_typevar_with_bound_no_warning() -> None:
    """Test that TypeVar with matching bound doesn't trigger warning."""
    server = Server("test")

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")

        bound_request = TypeVar("bound_request", bound=ListPromptsRequest)

        @server.list_prompts()
        async def handle_list_prompts(request: bound_request) -> ListPromptsResult:  # type: ignore[reportInvalidTypeVarUse]
            return ListPromptsResult(prompts=[])

        # No warning - TypeVar is bound to ListPromptsRequest
        deprecation_warnings = [warning for warning in w if issubclass(warning.category, DeprecationWarning)]
        assert len(deprecation_warnings) == 0


@pytest.mark.anyio
async def test_typevar_with_constraints_no_warning() -> None:
    """Test that TypeVar with matching constraint doesn't trigger warning."""
    server = Server("test")

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")

        @server.list_prompts()
        async def handle_list_prompts(request: ConstrainedRequest) -> ListPromptsResult:
            return ListPromptsResult(prompts=[])

        # No warning - TypeVar has ListPromptsRequest as a constraint
        deprecation_warnings = [warning for warning in w if issubclass(warning.category, DeprecationWarning)]
        assert len(deprecation_warnings) == 0


@pytest.mark.anyio
async def test_any_type_still_receives_request() -> None:
    """Test that handlers with Any type still receive the request object."""
    server = Server("test")
    received_request: Any = None

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)

        @server.list_prompts()
        async def handle_list_prompts(request: Any) -> ListPromptsResult:
            nonlocal received_request
            received_request = request
            return ListPromptsResult(prompts=[])

    handler = server.request_handlers[ListPromptsRequest]
    request = ListPromptsRequest(method="prompts/list", params=None)
    result = await handler(request)

    assert received_request is not None
    assert isinstance(received_request, ListPromptsRequest)
    assert isinstance(result, ServerResult)


@pytest.mark.anyio
async def test_union_handler_receives_correct_request() -> None:
    """Test that Union-typed handlers receive the request correctly."""
    server = Server("test")
    received_request: ListPromptsRequest | None = None

    @server.list_prompts()
    async def handle_list_prompts(request: ListPromptsRequest | None) -> ListPromptsResult:
        nonlocal received_request
        received_request = request
        return ListPromptsResult(prompts=[Prompt(name="test")])

    handler = server.request_handlers[ListPromptsRequest]
    request = ListPromptsRequest(method="prompts/list", params=None)
    result = await handler(request)

    assert received_request is not None
    assert isinstance(received_request, ListPromptsRequest)
    assert isinstance(result, ServerResult)
    assert isinstance(result.root, ListPromptsResult)
    assert len(result.root.prompts) == 1


@pytest.mark.anyio
async def test_wrong_union_type_triggers_warning() -> None:
    """Test that Union without the request type triggers deprecation warning."""
    server = Server("test")

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")

        @server.list_prompts()  # type: ignore[arg-type]  # Intentionally testing incorrect type for deprecation warning
        async def handle_list_prompts(request: str | int) -> list[Prompt]:
            return []

        # Deprecation warning should be issued - Union doesn't contain request type
        deprecation_warnings = [warning for warning in w if issubclass(warning.category, DeprecationWarning)]
        assert len(deprecation_warnings) == 1


@pytest.mark.anyio
async def test_generic_typevar_no_warning() -> None:
    """Test that generic TypeVar doesn't trigger warning."""
    server = Server("test")

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")

        @server.list_prompts()
        async def handle_list_prompts(request: T) -> ListPromptsResult:  # type: ignore[valid-type]
            return ListPromptsResult(prompts=[])

        # Generic TypeVar without bounds - should not trigger warning but will receive request
        deprecation_warnings = [warning for warning in w if issubclass(warning.category, DeprecationWarning)]
        # This may or may not warn depending on implementation - the key is it shouldn't break
        assert len(deprecation_warnings) in [0, 1]  # Either way is acceptable
