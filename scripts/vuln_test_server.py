#!/usr/bin/env python3
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs


PORT = 4321


INSECURE_INLINE_JS = r"""
<script>
// Vulnerable: reflects location.hash into innerHTML
function renderHash() {
  var target = document.getElementById('out');
  target.innerHTML = location.hash.substring(1);
}
// Vulnerable: uses eval on query param `code`
function runCode() {
  var params = new URLSearchParams(location.search);
  var code = params.get('code');
  if (code) { eval(code); }
}
window.onload = function() { renderHash(); runCode(); };
</script>
"""


EXTERNAL_JS = r"""
// Vulnerable: dynamic Function and document.write
var payload = window.name || '';
if (payload) {
  document.write('<div>' + payload + '</div>');
}
var x = new Function('return "pwned:" + Date.now()')();
console.log(x);
"""


HTML_PAGE = f"""
<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Vulnerable Test App</title>
    <script src="/static/app.js"></script>
  </head>
  <body>
    <h1>Vulnerable Test App</h1>
    <div id="out">placeholder</div>
    {INSECURE_INLINE_JS}
    <p>Try: #<script>alert(1)</script> or ?code=alert(2)</p>
  </body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def _send(self, code=200, body="", content_type="text/html"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # Simple routing
        if path == "/":
            return self._send(200, HTML_PAGE, "text/html; charset=utf-8")

        if path == "/static/app.js":
            return self._send(200, EXTERNAL_JS, "application/javascript; charset=utf-8")

        if path == "/api/keys":
            # Deliberately exposes secrets for testing
            data = {
                "api_key": "AKIAEXPOSEDKEY000000",
                "google_api_key": "AIzaSyDUMMYKEY-EXPOSED-12345678901234567",
                "jwt_secret": "supersecretjwtkey_super_insecure",
            }
            return self._send(200, json.dumps(data), "application/json")

        if path == "/api/login":
            # Echoes credentials (insecure) for testing
            qs = parse_qs(parsed.query)
            resp = {
                "username": qs.get("username", [""])[0],
                "password": qs.get("password", [""])[0],
                "note": "Credentials echoed back (intentionally insecure for testing)"
            }
            return self._send(200, json.dumps(resp), "application/json")

        if path == "/robots.txt":
            return self._send(200, "Disallow: /admin\nDisallow: /backup.zip\n", "text/plain")

        return self._send(404, "Not Found", "text/plain")

    def log_message(self, fmt, *args):
        # Quiet handler output
        pass


def main():
    httpd = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"[*] Vulnerable test server running at http://localhost:{PORT}")
    print("[*] Endpoints:")
    print("  /                -> HTML with vulnerable inline JS")
    print("  /static/app.js   -> Vulnerable external JS")
    print("  /api/keys        -> Exposes API keys/secrets (JSON)")
    print("  /api/login       -> Echoes username/password query params")
    print("  /robots.txt      -> Hints to hidden paths")
    httpd.serve_forever()


if __name__ == "__main__":
    main()


