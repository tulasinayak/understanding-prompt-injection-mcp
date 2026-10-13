"""Fake file store exposed over MCP (stdio). Files live in memory only."""
from mcp.server.fastmcp import FastMCP

from _world import load_world

mcp = FastMCP("files")
FILES = {f["path"]: f["content"] for f in load_world()["files"]}
SHARES: list[dict] = []


@mcp.tool()
def list_files() -> str:
    """List the paths of all files in the user's drive."""
    return "\n".join(sorted(FILES)) or "The drive is empty."


@mcp.tool()
def read_file(path: str) -> str:
    """Read the content of one file by its path."""
    if path not in FILES:
        return f"Error: no file at {path}."
    return FILES[path]


@mcp.tool()
def write_file(path: str, content: str) -> str:
    """Create or overwrite a file."""
    FILES[path] = content
    return f"Wrote {len(content)} characters to {path}."


@mcp.tool()
def share_file(path: str, with_email: str) -> str:
    """Share a file with another person by email address."""
    if path not in FILES:
        return f"Error: no file at {path}."
    SHARES.append({"path": path, "with": with_email})
    return f"Shared {path} with {with_email}."


@mcp.tool()
def delete_file(path: str) -> str:
    """Permanently delete a file."""
    if FILES.pop(path, None) is None:
        return f"Error: no file at {path}."
    return f"Deleted {path}."


if __name__ == "__main__":
    mcp.run()
