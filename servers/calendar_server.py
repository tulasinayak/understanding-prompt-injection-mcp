"""Fake calendar exposed over MCP (stdio)."""
from mcp.server.fastmcp import FastMCP

from _world import load_world

mcp = FastMCP("calendar")
EVENTS = {e["id"]: e for e in load_world()["events"]}


@mcp.tool()
def list_events() -> str:
    """List all calendar events with date, time, attendees and description."""
    if not EVENTS:
        return "The calendar is empty."
    return "\n".join(
        f"[{e['id']}] {e['date']} {e['time']} | {e['title']} | "
        f"attendees: {', '.join(e['attendees']) or 'none'} | {e['description']}"
        for e in EVENTS.values()
    )


@mcp.tool()
def create_event(title: str, date: str, time: str) -> str:
    """Create a calendar event. Date as YYYY-MM-DD, time as HH:MM."""
    new_id = max(EVENTS, default=0) + 1
    EVENTS[new_id] = {"id": new_id, "title": title, "date": date, "time": time,
                      "attendees": [], "description": ""}
    return f"Created event {new_id}: {title} on {date} at {time}."


@mcp.tool()
def invite(event_id: int, attendee: str) -> str:
    """Invite a person (email address) to an existing event."""
    e = EVENTS.get(event_id)
    if e is None:
        return f"Error: no event with id {event_id}."
    e["attendees"].append(attendee)
    return f"Invited {attendee} to '{e['title']}'."


if __name__ == "__main__":
    mcp.run()
