import warnings

import pytest

from mcp.server import Server
from mcp.types import (
    ListPromptsRequest,
    ListPromptsResult,
    ListResourcesRequest,
    ListResourcesResult,
    ListToolsRequest,
    ListToolsResult,
    PaginatedRequestParams,
    Prompt,
    Resource,
    ServerResult,
    Tool,
)


@pytest.mark.anyio
async def test_list_prompts_with_typed_request_no_warning() -> None:
    """Test that properly typed handlers don't trigger deprecation warnings."""
    server = Server("test")

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")

        @server.list_prompts()
        async def handle_list_prompts(request: ListPromptsRequest) -> ListPromptsResult:
            return ListPromptsResult(prompts=[])

        # No deprecation warning should be issued
        assert len([warning for warning in w if issubclass(warning.category, DeprecationWarning)]) == 0


@pytest.mark.anyio
async def test_list_prompts_without_params_triggers_warning() -> None:
    """Test that handlers without parameters trigger deprecation warnings."""
    server = Server("test")

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")

        @server.list_prompts()
        async def handle_list_prompts() -> list[Prompt]:
            return []

        # A deprecation warning should be issued
        deprecation_warnings = [warning for warning in w if issubclass(warning.category, DeprecationWarning)]
        assert len(deprecation_warnings) == 1
        assert "ListPromptsRequest" in str(deprecation_warnings[0].message)


@pytest.mark.anyio
async def test_list_prompts_with_untyped_param_triggers_warning() -> None:
    """Test that handlers with untyped parameters trigger deprecation warnings."""
    server = Server("test")

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")

        @server.list_prompts()
        async def handle_list_prompts(request) -> ListPromptsResult:  # type: ignore[no-untyped-def]
            return ListPromptsResult(prompts=[])

        # A deprecation warning should be issued
        deprecation_warnings = [warning for warning in w if issubclass(warning.category, DeprecationWarning)]
        assert len(deprecation_warnings) == 1
        assert "ListPromptsRequest" in str(deprecation_warnings[0].message)


@pytest.mark.anyio
async def test_list_resources_with_typed_request_no_warning() -> None:
    """Test that properly typed resource handlers don't trigger warnings."""
    server = Server("test")

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")

        @server.list_resources()
        async def handle_list_resources(request: ListResourcesRequest) -> ListResourcesResult:
            return ListResourcesResult(resources=[])

        # No deprecation warning should be issued
        assert len([warning for warning in w if issubclass(warning.category, DeprecationWarning)]) == 0


@pytest.mark.anyio
async def test_list_resources_without_params_triggers_warning() -> None:
    """Test that resource handlers without parameters trigger deprecation warnings."""
    server = Server("test")

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")

        @server.list_resources()
        async def handle_list_resources() -> list[Resource]:
            return []

        # A deprecation warning should be issued
        deprecation_warnings = [warning for warning in w if issubclass(warning.category, DeprecationWarning)]
        assert len(deprecation_warnings) == 1
        assert "ListResourcesRequest" in str(deprecation_warnings[0].message)


@pytest.mark.anyio
async def test_list_tools_with_typed_request_no_warning() -> None:
    """Test that properly typed tool handlers don't trigger warnings."""
    server = Server("test")

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")

        @server.list_tools()
        async def handle_list_tools(request: ListToolsRequest) -> ListToolsResult:
            return ListToolsResult(tools=[])

        # No deprecation warning should be issued
        assert len([warning for warning in w if issubclass(warning.category, DeprecationWarning)]) == 0


@pytest.mark.anyio
async def test_list_tools_without_params_triggers_warning() -> None:
    """Test that tool handlers without parameters trigger deprecation warnings."""
    server = Server("test")

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")

        @server.list_tools()
        async def handle_list_tools() -> list[Tool]:
            return []

        # A deprecation warning should be issued
        deprecation_warnings = [warning for warning in w if issubclass(warning.category, DeprecationWarning)]
        assert len(deprecation_warnings) == 1
        assert "ListToolsRequest" in str(deprecation_warnings[0].message)


@pytest.mark.anyio
async def test_old_style_handler_still_works() -> None:
    """Test that old-style handlers still work (with deprecation warning)."""
    server = Server("test")

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")

        @server.list_prompts()
        async def handle_list_prompts() -> list[Prompt]:
            return [Prompt(name="test", description="Test prompt")]

        # Handler should be registered
        assert ListPromptsRequest in server.request_handlers

        # Deprecation warning should be issued
        deprecation_warnings = [warning for warning in w if issubclass(warning.category, DeprecationWarning)]
        assert len(deprecation_warnings) == 1

        # Handler should still work correctly
        handler = server.request_handlers[ListPromptsRequest]
        request = ListPromptsRequest(method="prompts/list", params=None)
        result = await handler(request)

        assert isinstance(result, ServerResult)
        assert isinstance(result.root, ListPromptsResult)
        assert len(result.root.prompts) == 1
        assert result.root.prompts[0].name == "test"


@pytest.mark.anyio
async def test_new_style_handler_receives_pagination_params() -> None:
    """Test that new-style handlers receive pagination parameters correctly."""
    server = Server("test")
    received_request: ListPromptsRequest | None = None

    @server.list_prompts()
    async def handle_list_prompts(request: ListPromptsRequest) -> ListPromptsResult:
        nonlocal received_request
        received_request = request
        return ListPromptsResult(prompts=[], nextCursor="next-page")

    handler = server.request_handlers[ListPromptsRequest]

    # Test with cursor
    cursor_value = "test-cursor-123"
    request_with_cursor = ListPromptsRequest(method="prompts/list", params=PaginatedRequestParams(cursor=cursor_value))
    result = await handler(request_with_cursor)

    assert received_request is not None
    assert received_request.params is not None
    assert received_request.params.cursor == cursor_value
    assert isinstance(result, ServerResult)
    assert result.root.nextCursor == "next-page"
