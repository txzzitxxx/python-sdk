"""
FastMCP Echo Server
"""

from mcp.server.fastmcp import FastMCP,Context

# Create server
mcp = FastMCP("Echo Server")


@mcp.tool()
def echo(text: str, ctx: Context) -> str:
    """Echo the input text"""
    ctx.request_context.request.query_params.get("session_id")
    return text

mcp.run(transport="sse")