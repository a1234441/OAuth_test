"""
Step1: GitHub OAuth Authorization Code Flow
- No OAuth-specific libraries
- Uses state generation + verification for CSRF protection
- Local HTTPS server: https://localhost:8443
  - /       : Home
  - /login  : Redirect to GitHub authorize endpoint
  - /callback : Validate state, exchange code for access token
"""

from __future__ import annotations

import html
import os
import secrets
import ssl
import sys
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Optional

import requests


# ===== Config =====
HOST = "localhost"
PORT = 8443
BASE_URL = f"https://{HOST}:{PORT}"
REDIRECT_URI = f"{BASE_URL}/callback"

AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
TOKEN_URL = "https://github.com/login/oauth/access_token"

SCOPE = "repo"  # 課題の後続(Repos/Issue)に必要。Step1だけなら空でも良いが、ここで付けておく。

CERT_FILE = os.path.join("certs", "localhost.crt")
KEY_FILE = os.path.join("certs", "localhost.key")


def require_env(name: str) -> str:
    v = os.environ.get(name, "").strip()
    if not v:
        raise RuntimeError(f"Missing env var: {name}")
    return v


CLIENT_ID = ""
CLIENT_SECRET = ""

# ===== In-memory state/token (no persistence) =====
EXPECTED_STATE: Optional[str] = None
ACCESS_TOKEN: Optional[str] = None


def mask_token(token: str) -> str:
    if len(token) <= 10:
        return "*" * len(token)
    return token[:6] + "*" * (len(token) - 10) + token[-4:]


def build_ssl_context() -> ssl.SSLContext:
    if not (os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE)):
        raise RuntimeError(
            "TLS certificate not found.\n"
            f"Expected:\n  {CERT_FILE}\n  {KEY_FILE}\n"
            "Create them with OpenSSL (see instructions)."
        )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    return ctx


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("[%s] %s\n" % (self.address_string(), fmt % args))

    def send_html(self, status: int, body: str) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, location: str) -> None:
        self.send_response(HTTPStatus.FOUND)
        self.send_header("Location", location)
        self.end_headers()

    def route_path(self) -> str:
        return urllib.parse.urlparse(self.path).path

    def parse_query(self) -> Dict[str, str]:
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        return {k: (v[0] if v else "") for k, v in qs.items()}

    def do_GET(self) -> None:
        p = self.route_path()
        if p == "/":
            self.handle_home()
        elif p == "/login":
            self.handle_login()
        elif p == "/callback":
            self.handle_callback()
        else:
            self.send_html(HTTPStatus.NOT_FOUND, "<h1>404</h1>")

    def handle_home(self) -> None:
        status = "✅ token acquired" if ACCESS_TOKEN else "❌ no token"
        token_view = html.escape(mask_token(ACCESS_TOKEN)) if ACCESS_TOKEN else ""
        body = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>OAuth Step1</title></head>
<body>
  <h1>OAuth Step1</h1>
  <p>Status: {status}</p>
  <p>Token: {token_view}</p>
  <ul>
    <li><a href="/login">Login with GitHub</a></li>
  </ul>
  <hr>
  <p style="color:#666;">{html.escape(BASE_URL)}</p>
</body></html>"""
        self.send_html(HTTPStatus.OK, body)

    def handle_login(self) -> None:
        global EXPECTED_STATE
        # CSRF対策: 推測困難なstate生成 → callbackで一致検証
        EXPECTED_STATE = secrets.token_urlsafe(32)

        params = {
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "scope": SCOPE,
            "state": EXPECTED_STATE,
        }
        url = AUTHORIZE_URL + "?" + urllib.parse.urlencode(params)
        self.redirect(url)

    def handle_callback(self) -> None:
        global EXPECTED_STATE, ACCESS_TOKEN

        q = self.parse_query()
        err = q.get("error", "")
        if err:
            desc = q.get("error_description", "")
            self.send_html(
                HTTPStatus.BAD_REQUEST,
                f"<h1>OAuth Error</h1><p>{html.escape(err)} {html.escape(desc)}</p>",
            )
            return

        code = q.get("code", "")
        state = q.get("state", "")

        if not code or not state:
            self.send_html(HTTPStatus.BAD_REQUEST, "<h1>Missing code/state</h1>")
            return

        if not EXPECTED_STATE or not secrets.compare_digest(state, EXPECTED_STATE):
            # state不一致 → CSRF/リプレイ疑い
            self.send_html(HTTPStatus.FORBIDDEN, "<h1>Invalid state (CSRF suspected)</h1>")
            return

        # code → access_token 交換
        try:
            headers = {"Accept": "application/json", "User-Agent": "oauth-step1/1.0"}
            data = {
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "state": state,
            }
            r = requests.post(TOKEN_URL, data=data, headers=headers, timeout=15)
            r.raise_for_status()
            token_json = r.json()
            if "error" in token_json:
                raise RuntimeError(str(token_json))

            ACCESS_TOKEN = token_json.get("access_token")
            # 使い捨てのstateは破棄（リプレイ耐性）
            EXPECTED_STATE = None

            if ACCESS_TOKEN:
                # デモ用にフルtokenはコンソール出力（提出/本番なら出さない方針でもOK）
                print("ACCESS_TOKEN:", ACCESS_TOKEN)

            self.redirect("/")
        except Exception as e:
            self.send_html(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                f"<h1>Token exchange failed</h1><pre>{html.escape(str(e))}</pre>",
            )


def main() -> None:
    #powershell環境からキーを取得する
    global CLIENT_ID, CLIENT_SECRET
    CLIENT_ID = require_env("GITHUB_CLIENT_ID")
    CLIENT_SECRET = require_env("GITHUB_CLIENT_SECRET")

    #
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    httpd.socket = build_ssl_context().wrap_socket(httpd.socket, server_side=True)

    print(f"Serving on {BASE_URL}")
    print("Open the URL in your browser -> click 'Login with GitHub'.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
