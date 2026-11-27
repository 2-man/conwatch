"""ConWatch module SDK for Python (single file, no dependencies).

    from conwatch_sdk import Module

    m = Module()

    @m.on("connection_opened")
    def opened(ev):
        if ev["remote_port"] == 23:
            m.alert(f"{ev['process']} used telnet", level="critical")

    m.run()
"""
import json
import sys


class Module:
    def __init__(self):
        self._handlers = {}

    def on(self, event_type):
        """Decorator: register a handler for events with the given `type`
        ("connection_opened", "connection_closed", "app_first_seen",
        "traffic_sample", "device_seen", "alert", or "*" for all)."""
        def deco(fn):
            self._handlers.setdefault(event_type, []).append(fn)
            return fn
        return deco

    def _send(self, obj):
        sys.stdout.write(json.dumps(obj) + "\n")
        sys.stdout.flush()

    def alert(self, message, level="info"):
        """Needs the `alerts:emit` permission. level: info | warning | critical."""
        self._send({"action": "alert", "level": level, "message": message})

    def log(self, message):
        self._send({"action": "log", "message": message})

    def run(self):
        """Blocks, dispatching events from ConWatch until stdin closes."""
        for line in sys.stdin:
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            for key in (ev.get("type"), "*"):
                for fn in self._handlers.get(key, []):
                    fn(ev)
