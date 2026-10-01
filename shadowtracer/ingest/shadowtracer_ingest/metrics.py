"""Thread-safe counters exposed over plain HTTP (stdlib only - no need for
a prometheus_client dependency just to publish a handful of integers)."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Metrics:
    def __init__(self, **initial):
        self._lock = threading.Lock()
        self._counts = dict(initial)

    def incr(self, name, by=1):
        with self._lock:
            self._counts[name] = self._counts.get(name, 0) + by

    def set(self, name, value):
        with self._lock:
            self._counts[name] = value

    def snapshot(self):
        with self._lock:
            return dict(self._counts)


def serve_metrics(metrics: Metrics, port: int) -> ThreadingHTTPServer:
    """Starts a background HTTP server returning metrics.snapshot() as JSON
    on any path. Returns the server so the caller can .shutdown() it."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = json.dumps(metrics.snapshot()).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass  # don't spam stdout for every metrics scrape

    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server
