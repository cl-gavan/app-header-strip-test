"""
auth-header-check: a CML Application that reports whether the Authorization:
Bearer header is visible after passing through Knox + the Authorizer.

Test with:
    curl -H "Authorization: Bearer <jwt>" https://<app-url>/
"""

import os

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def check(path: str):
    auth_value = request.headers.get("Authorization", "")
    auth_present = auth_value.lower().startswith("bearer ")

    return jsonify(
        {
            "authorization_header_present": auth_present,
            "authorization_header": auth_value or None,
            "headers": dict(request.headers),
        }
    )


if __name__ == "__main__":
    port = int(os.environ.get("APP_PORT", 8080))
    app.run(host="0.0.0.0", port=port)
