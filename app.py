"""
auth-header-check: a CML Application that reports whether the Authorization:
Bearer header is visible after passing through Knox + the Authorizer.

Deploy as a CML Application and visit it in a browser. The page shows a
clear PRESENT / STRIPPED indicator and a full dump of every header the
application receives, so you can verify both that the Bearer token is gone
and that the x-cdp-actor-* identity headers are in place.
"""

import os

from flask import Flask, jsonify, render_template_string, request

app = Flask(__name__)

_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Authorization Header Check</title>
  <style>
    body { font-family: monospace; margin: 2rem; background: #f5f5f5; }
    h1   { color: #333; }
    .banner {
      display: inline-block;
      padding: 1rem 2rem;
      border-radius: 6px;
      font-size: 1.5rem;
      font-weight: bold;
      margin-bottom: 2rem;
    }
    .present  { background: #f8d7da; color: #721c24; border: 2px solid #f5c6cb; }
    .stripped { background: #d4edda; color: #155724; border: 2px solid #c3e6cb; }
    table { border-collapse: collapse; width: 100%; background: white; }
    th { background: #343a40; color: white; text-align: left; padding: 0.5rem 1rem; }
    td { padding: 0.5rem 1rem; border-bottom: 1px solid #dee2e6; word-break: break-all; }
    tr.highlight td { background: #fff3cd; font-weight: bold; }
    tr.identity  td { background: #d1ecf1; }
    tr:hover td  { background: #f1f1f1; }
    .path { color: #555; margin-bottom: 1.5rem; }
  </style>
</head>
<body>
  <h1>Authorization Header Check</h1>
  <p class="path">{{ method }} {{ path }}</p>

  {% if auth_present %}
  <div class="banner present">
    &#x26A0; Authorization: Bearer &mdash; PRESENT (header was NOT stripped)
  </div>
  {% else %}
  <div class="banner stripped">
    &#x2713; Authorization: Bearer &mdash; STRIPPED (header not visible to application)
  </div>
  {% endif %}

  <h2>Received Headers</h2>
  <table>
    <tr><th>Header</th><th>Value</th></tr>
    {% for name, value in headers %}
    <tr class="{{ row_class(name) }}">
      <td>{{ name }}</td>
      <td>{{ value }}</td>
    </tr>
    {% endfor %}
  </table>
</body>
</html>"""


def _row_class(name: str) -> str:
    lower = name.lower()
    if lower == "authorization":
        return "highlight"
    if lower.startswith("x-cdp-actor") or lower == "x-caii-authorized":
        return "identity"
    return ""


@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def check(path: str):
    headers = sorted(request.headers.items())
    auth_value = request.headers.get("Authorization", "")
    auth_present = auth_value.lower().startswith("bearer ")

    if "application/json" in request.headers.get("Accept", ""):
        return jsonify(
            {
                "authorization_header_present": auth_present,
                "authorization_header": auth_value or None,
                "headers": dict(headers),
            }
        )

    return render_template_string(
        _HTML,
        method=request.method,
        path="/" + path,
        headers=headers,
        auth_present=auth_present,
        row_class=_row_class,
    )


if __name__ == "__main__":
    port = int(os.environ.get("CDSW_APP_PORT", 8080))
    app.run(host="0.0.0.0", port=port)
