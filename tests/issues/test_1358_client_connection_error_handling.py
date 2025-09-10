"""Test for handling invalid URIs in streamablehttp_client (Issue #1358)."""

from contextlib import AsyncExitStack

import pytest

from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client


@pytest.mark.anyio
async def test_invalid_uri_without_protocol():
    """Test that invalid URIs without protocol raise proper exceptions."""
    exit_stack = AsyncExitStack()

    async with exit_stack:
        # Test with URI missing protocol - should raise an exception
        with pytest.raises(BaseException) as exc_info:
            (read_stream, write_stream, _) = await exit_stack.enter_async_context(streamablehttp_client("invalid_uri"))
            session = await exit_stack.enter_async_context(ClientSession(read_stream, write_stream))
            await session.initialize()

        assert "Failed to send POST request" in str(exc_info.value)


@pytest.mark.anyio
async def test_invalid_uri_with_unreachable_host():
    """Test that URIs with unreachable hosts raise proper exceptions."""
    exit_stack = AsyncExitStack()

    async with exit_stack:
        # Test with valid protocol but unreachable host
        with pytest.raises(BaseException) as exc_info:
            (read_stream, write_stream, _) = await exit_stack.enter_async_context(
                streamablehttp_client("http://127.0.0.1:99999/")
            )
            session = await exit_stack.enter_async_context(ClientSession(read_stream, write_stream))
            await session.initialize()

        assert "Failed to send POST request" in str(exc_info.value)
