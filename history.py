"""Local SMB Sentinel scan history."""
from __future__ import annotations
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MAX_HISTORY = 50
DEFAULT_PATH = Path.home() / ".smb-sentinel-history.json"


def load_history(path: str | Path = DEFAULT_PATH) -> list[dict[str, Any]]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return value[:MAX_HISTORY] if isinstance(value, list) else []


def save_snapshot(results: dict[str, dict[str, Any]], path: str | Path = DEFAULT_PATH) -> dict[str, Any]:
    """Save sanitized findings; never store credentials or packet payloads."""
    previous = load_history(path)
    rows = []
    for ip, result in sorted(results.items()):
        rows.append({
            "ip": str(ip),
            "risk_level": str(result.get("risk_level", "unknown")),
            "findings": [str(item) for item in result.get("findings", [])],
            "port_open": bool(result.get("port_open")),
            "smb1_enabled": bool(result.get("smb1_enabled")),
            "smb2_supported": bool(result.get("smb2_supported")),
            "smb2_dialect": result.get("smb2_dialect"),
            "signing_enabled": result.get("signing_enabled"),
            "signing_required": result.get("signing_required"),
        })
    snapshot = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host_count": len(rows),
        "high_count": sum(1 for row in rows if row["risk_level"] == "high"),
        "medium_count": sum(1 for row in rows if row["risk_level"] == "medium"),
        "results": rows,
    }
    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    temp = file_path.with_suffix(file_path.suffix + ".tmp")
    temp.write_text(json.dumps([snapshot] + previous[:MAX_HISTORY-1], indent=2), encoding="utf-8")
    os.replace(temp, file_path)
    return {
        "timestamp": snapshot["timestamp"],
        "host_count": snapshot["host_count"],
        "high_count": snapshot["high_count"],
        "medium_count": snapshot["medium_count"],
        "previous_scans": len(previous),
    }
