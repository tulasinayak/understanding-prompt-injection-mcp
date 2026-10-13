"""Fake inbox exposed over MCP (stdio). Nothing here touches the network."""
from mcp.server.fastmcp import FastMCP

from _world import load_world

mcp = FastMCP("inbox")
EMAILS = {e["id"]: e for e in load_world()["emails"]}
SENT: list[dict] = []


@mcp.tool()
def list_emails() -> str:
    """List the emails in the inbox: id, sender and subject."""
    if not EMAILS:
        return "The inbox is empty."
    return "\n".join(f"[{e['id']}] from {e['from']} | {e['subject']}" for e in EMAILS.values())


@mcp.tool()
def read_email(email_id: int) -> str:
    """Read the full text of one email by its id."""
    e = EMAILS.get(email_id)
    if e is None:
        return f"Error: no email with id {email_id}."
    return f"From: {e['from']}\nSubject: {e['subject']}\n\n{e['body']}"


@mcp.tool()
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email from the user's account."""
    SENT.append({"to": to, "subject": subject, "body": body})
    return f"Email sent to {to}."


@mcp.tool()
def delete_email(email_id: int) -> str:
    """Permanently delete one email by its id."""
    if EMAILS.pop(email_id, None) is None:
        return f"Error: no email with id {email_id}."
    return f"Email {email_id} deleted."


if __name__ == "__main__":
    mcp.run()
