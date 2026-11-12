"""Load actions from a simple JSONL file or from a Claude Code session transcript (JSONL)."""
from __future__ import annotations

import json
from pathlib import Path

TOOL_MAP = {"bash": "bash", "read": "read", "write": "write", "edit": "write", "multiedit": "write",
            "webfetch": "fetch", "fetch": "fetch", "notebookedit": "write"}


def _from_tool_use(block: dict) -> dict | None:
    name = str(block.get("name", "")).lower()
    tool = TOOL_MAP.get(name)
    if not tool:
        return None
    inp = block.get("input") or {}
    text = inp.get("command") or inp.get("file_path") or inp.get("url") or json.dumps(inp)
    if tool == "write" and inp.get("file_path"):
        text = inp["file_path"]
    return {"id": block.get("id", ""), "tool": tool, "input": text}


def load_actions(path: str | Path) -> list[dict]:
    """Accepts either {"tool","input",...} lines or Claude Code transcript lines with tool_use blocks.
    For transcripts, the most recent tool_result text is attached as each action's "context"."""
    actions, last_output = [], ""
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if "tool" in row and "input" in row:
            actions.append(row)
            continue
        content = (row.get("message") or {}).get("content")
        if not isinstance(content, list):
            continue
        for block in content:
            if block.get("type") == "tool_result":
                c = block.get("content")
                last_output = c if isinstance(c, str) else " ".join(x.get("text", "") for x in (c or []) if isinstance(x, dict))
            elif block.get("type") == "tool_use":
                act = _from_tool_use(block)
                if act:
                    act["context"] = last_output[-4000:]
                    actions.append(act)
    return actions
