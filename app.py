"""
auth-header-check: a CML Application that reports whether the Authorization:
Bearer header is visible after passing through Knox + the Authorizer.

Test with:
    curl -H "Authorization: Bearer <jwt>" https://<app-url>/
"""

import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self._respond()

    def do_POST(self):
        self._respond()

    def _respond(self):
        headers = dict(self.headers)
        auth_value = headers.get("Authorization", "")
        auth_present = auth_value.lower().startswith("bearer ")

        body = json.dumps(
            {
                "authorization_header_present": auth_present,
                "authorization_header": auth_value or None,
                "headers": headers,
            },
            indent=2,
        ).encode()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print(fmt % args)


if __name__ == "__main__":
    port = int(os.environ.get("APP_PORT", 8080))
    server = HTTPServer(("0.0.0.0", port), Handler)
    print(f"Listening on port {port}")
    server.serve_forever()
