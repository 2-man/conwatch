"""Example ConWatch module.

Protocol: one JSON event per line on stdin; reply with JSON actions on stdout.
"""
import json
import sys

for line in sys.stdin:
    try:
        ev = json.loads(line)
    except ValueError:
        continue
    if ev.get("type") == "connection_opened" and ev.get("remote_port") == 23:
        print(json.dumps({
            "action": "alert",
            "level": "critical",
            "message": f"{ev['process']} connected to Telnet port at {ev['remote_addr']}",
        }), flush=True)
