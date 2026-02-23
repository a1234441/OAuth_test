"""
Step1: GitHub OAuth Authorization Code Flow
- No OAuth-specific libraries
- Uses state generation + verification for CSRF protection
- Local HTTPS server: https://localhost:8443
  - /       : Home
  - /login  : Redirect to GitHub authorize endpoint
  - /callback : Validate state, exchange code for access token

コマンド
  openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes `
  -keyout certs\localhost.key -out certs\localhost.crt `
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost"
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


#HTTPS通信をするために必要な証明書と秘密鍵を読み込んで、TLS(SSL)設定オブジェクトを作って返す
def build_ssl_context() -> ssl.SSLContext:
    if not (os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE)):
        raise RuntimeError(
            "TLS certificate not found.\n"
            f"Expected:\n  {CERT_FILE}\n  {KEY_FILE}\n"
            "Create them with OpenSSL (see instructions)."
        )
    #サーバ側(localhost:8443)のTSL設定を作る
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    #ctxに秘密鍵と証明書(TSL)を読み込む
    ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    return ctx


class Handler(BaseHTTPRequestHandler):
    def _html(self, status: int, body: str) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(data)

    def _redirect(self, url: str) -> None:
        self.send_response(302)
        self.send_header("Location", url)
        self.end_headers()

    def do_GET(self) -> None:
        global EXPECTED_STATE, ACCESS_TOKEN

        u = urllib.parse.urlsplit(self.path)
        path = u.path
        q = urllib.parse.parse_qs(u.query)

        if path == "/login":
            EXPECTED_STATE = secrets.token_urlsafe(32)
            params = {
                "client_id": CLIENT_ID,
                "redirect_uri": REDIRECT_URI,
                "scope": SCOPE,
                "state": EXPECTED_STATE,
            }
            self._redirect(AUTHORIZE_URL + "?" + urllib.parse.urlencode(params))
            return

        if path == "/callback":
            # error handling
            err = (q.get("error") or [""])[0]
            if err:
                desc = (q.get("error_description") or [""])[0]
                self._html(400, f"<h1>OAuth Error</h1><p>{html.escape(err)} {html.escape(desc)}</p>")
                return

            code = (q.get("code") or [""])[0]
            state = (q.get("state") or [""])[0]
            if not code or not state:
                self._html(400, "<h1>Missing code/state</h1>")
                return

            if not EXPECTED_STATE or not secrets.compare_digest(state, EXPECTED_STATE):
                self._html(403, "<h1>Invalid state (CSRF suspected)</h1>")
                return

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
                EXPECTED_STATE = None  # 使い捨て
                self._html(
                    200,
                    "<h1>OK</h1>"
                    f"<p>token: {html.escape(ACCESS_TOKEN[:6] + '...' if ACCESS_TOKEN else '')}</p>"
                    '<p><a href="/">Back</a></p>',
                )
            except Exception as e:
                self._html(500, f"<h1>Token exchange failed</h1><pre>{html.escape(str(e))}</pre>")
            return

        # default (/)
        status = "token acquired" if ACCESS_TOKEN else "no token"
        self._html(200, f"<h1>OAuth Step1</h1><p>{status}</p><a href='/login'>Login with GitHub</a>")


def main() -> None:
    #powershell環境からキーを取得する
    global CLIENT_ID, CLIENT_SECRET
    CLIENT_ID = require_env("GITHUB_CLIENT_ID")
    CLIENT_SECRET = require_env("GITHUB_CLIENT_SECRET")

    #待ち受け側のHttpサーバーの作成
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    #作ったサーバーをhttpsにする
    httpd.socket = build_ssl_context().wrap_socket(httpd.socket, server_side=True)

    #サーバーを止めるまで動かし続ける
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
