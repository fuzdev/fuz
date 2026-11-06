#!/usr/bin/env python3
"""
Fuz Python Sidecar
Long-running process for Python tools. Communicates via JSON-lines over stdio.
"""

import json
import sys
import time
from typing import Any

# Version constants - keep in sync with dependencies
VERSIONS = {
    # Add dependency versions here as tools are added
}


def dispatch(tool: str, content: str, options: dict | None = None) -> Any:
    """Dispatch a tool request and return the result."""
    match tool:
        case "__version_info":
            return {
                "runtime": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
                "dependencies": VERSIONS,
            }
        case "hello-python":
            # Hello world: computes 21 * 2
            return {"message": "Hello from Python!", "result": 21 * 2}
        case _:
            raise ValueError(f"Unknown tool: {tool}")


def main():
    """Main loop: read JSON-lines from stdin, process, write responses to stdout."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        req = json.loads(line)
        start = time.perf_counter()

        try:
            output = dispatch(req["tool"], req["content"], req.get("options"))
            response = {
                "id": req["id"],
                "ok": True,
                "output": output,
                "duration_ms": round((time.perf_counter() - start) * 1000),
            }
        except Exception as e:
            response = {
                "id": req["id"],
                "ok": False,
                "error": str(e),
                "duration_ms": round((time.perf_counter() - start) * 1000),
            }

        print(json.dumps(response), flush=True)


if __name__ == "__main__":
    main()
