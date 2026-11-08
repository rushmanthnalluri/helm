"""Homie Model Context Protocol (MCP) Server.
Exposes Homie's native Windows workstation capabilities as standard MCP tools
for Claude Desktop, Claude Code, Cursor, Antigravity, and any other AI agent:
- Screen memory timeline search (Screenpipe-style)
- Window placement and snapping across monitors
- Real-time PC vitals and active process management
- High-resolution display screen captures
- WASAPI loopback meeting audio intelligence & transcripts
- Clipboard read and write synchronization
- Application launching and window focus

Complies with Model Context Protocol specification (JSON-RPC 2.0).
"""

import os
import sys
import json
import time
import base64
import logging

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import windows_tools
import semantic_screen_memory
import quick_notes
import meeting_notes

logger = logging.getLogger("homie.mcp")

# MCP Tool Definitions
MCP_TOOLS = [
    {
        "name": "homie_get_vitals",
        "description": "Returns current Windows PC vitals including CPU usage, RAM utilization, battery status, active foreground window, and user idle seconds.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "homie_snap_window",
        "description": "Positions and snaps an application window to a specific screen region (e.g. 'left', 'right', 'top', 'bottom', 'maximize', 'center').",
        "inputSchema": {
            "type": "object",
            "properties": {
                "app_name": {
                    "type": "string",
                    "description": "The name or title of the application window, e.g. 'chrome', 'code', 'spotify'"
                },
                "position": {
                    "type": "string",
                    "enum": ["left", "right", "top", "bottom", "maximize", "center"],
                    "description": "The target screen position"
                }
            },
            "required": ["app_name", "position"]
        }
    },
    {
        "name": "homie_read_screen_memory",
        "description": "Searches the local timeline of everything the user has looked at, read, or edited on screen over recent history.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "The search keyword, window title, or text to find in screen memory"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of history events to return (default 5)"
                }
            },
            "required": ["query"]
        }
    },
    {
        "name": "homie_get_clipboard",
        "description": "Reads the current plain text contents of the Windows clipboard.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "homie_set_clipboard",
        "description": "Sets the Windows clipboard text to the provided content.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "The text to copy to the Windows clipboard"
                }
            },
            "required": ["text"]
        }
    },
    {
        "name": "homie_capture_screen",
        "description": "Takes a high-resolution screenshot of all connected Windows monitors and returns the file path.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "homie_get_meeting_notes",
        "description": "Retrieves recent meeting audio transcripts and summaries recorded via WASAPI system loopback.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Number of recent meeting sessions to retrieve (default 3)"
                }
            },
            "required": []
        }
    },
    {
        "name": "homie_list_windows",
        "description": "Lists all visible, non-minimized desktop application windows with their titles and process IDs.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "filter_query": {
                    "type": "string",
                    "description": "Optional substring filter for window title or process name"
                }
            },
            "required": []
        }
    },
    {
        "name": "homie_launch_app",
        "description": "Launches a Windows program or brings its existing instance into the foreground.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "app_name": {
                    "type": "string",
                    "description": "The application name, e.g. 'notepad', 'chrome', 'calc', 'explorer'"
                }
            },
            "required": ["app_name"]
        }
    }
]

def execute_mcp_tool(name, arguments):
    """Executes an MCP tool call and returns result text."""
    try:
        if name == "homie_get_vitals":
            vitals = windows_tools.get_system_vitals()
            return json.dumps(vitals, indent=2)

        elif name == "homie_snap_window":
            app = arguments.get("app_name", "")
            pos = arguments.get("position", "left")
            ok, msg = windows_tools.place_window(app, pos)
            return f"Success: {ok}. {msg}"

        elif name == "homie_read_screen_memory":
            q = arguments.get("query", "")
            lim = int(arguments.get("limit", 5))
            hits = semantic_screen_memory.search_screen_history(q, limit=lim)
            if not hits:
                return f"No occurrences of '{q}' found in screen timeline memory."
            lines = [f"Found {len(hits)} occurrences of '{q}' in screen memory:"]
            for h in hits:
                lines.append(f"• [{h['time_str']}] {h['proc_name']} — {h['window_title']}")
            return "\n".join(lines)

        elif name == "homie_get_clipboard":
            text = windows_tools.get_clipboard_text()
            return text if text else "(Clipboard is empty)"

        elif name == "homie_set_clipboard":
            txt = arguments.get("text", "")
            ok, msg = windows_tools.set_clipboard_text(txt)
            return f"Clipboard updated ({len(txt)} chars)" if ok else f"Failed: {msg}"

        elif name == "homie_capture_screen":
            paths = windows_tools.capture_screens()
            return f"Captured {len(paths)} display screenshot(s): " + ", ".join(paths)

        elif name == "homie_get_meeting_notes":
            lim = int(arguments.get("limit", 3))
            sessions = meeting_notes.get_recent_meetings(limit=lim)
            if not sessions:
                return "No meeting sessions recorded."
            lines = []
            for s in sessions:
                lines.append(f"### {s['title']} ({s['date_str']}, {s['duration_formatted']})\n{s['summary']}")
            return "\n\n".join(lines)

        elif name == "homie_list_windows":
            q = arguments.get("filter_query", "")
            wins = windows_tools.find_windows(q)
            if not wins:
                return "No visible windows matched."
            lines = [f"Found {len(wins)} windows:"]
            for w in wins[:20]:
                lines.append(f"• [{w['pid']}] {w['proc_name']}: {w['title']}")
            return "\n".join(lines)

        elif name == "homie_launch_app":
            app = arguments.get("app_name", "")
            ok, msg = windows_tools.launch_app(app)
            return f"Launch result: {msg}"

        else:
            return f"Error: Unknown tool '{name}'"

    except Exception as e:
        logger.error("Error executing MCP tool %s: %s", name, e)
        return f"Error: {e}"

def handle_jsonrpc_request(req):
    """Processes a single JSON-RPC 2.0 MCP request."""
    method = req.get("method", "")
    req_id = req.get("id")

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "homie-workstation",
                    "version": "1.0.0"
                }
            }
        }

    elif method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": MCP_TOOLS
            }
        }

    elif method == "tools/call":
        params = req.get("params", {})
        tool_name = params.get("name", "")
        tool_args = params.get("arguments", {})
        result_text = execute_mcp_tool(tool_name, tool_args)
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": str(result_text)
                    }
                ]
            }
        }

    elif method == "notifications/initialized":
        return None  # No response needed for notifications

    else:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32601,
                "message": f"Method '{method}' not found"
            }
        }

def run_stdio_mcp_server():
    """Runs standard MCP server over stdin/stdout for desktop AI agents."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            res = handle_jsonrpc_request(req)
            if res is not None:
                sys.stdout.write(json.dumps(res) + "\n")
                sys.stdout.flush()
        except Exception as e:
            err_res = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {e}"}
            }
            sys.stdout.write(json.dumps(err_res) + "\n")
            sys.stdout.flush()

if __name__ == "__main__":
    run_stdio_mcp_server()
