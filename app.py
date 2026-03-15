"""
Step1: GitHub OAuth Authorization Code Flow
- No OAuth-specific libraries
- Uses state generation + verification for CSRF protection
- Local HTTPS server: https://localhost:8443
  - /       : Home
  - /login  : Redirect to GitHub authorize endpoint
  - /callback : Validate state, exchange code for access token

Step2: レポジトリ一覧の取得（プライベート含む）
  - /repos  : API経由で repos を取得して画面表示（selectで選ぶ）

Step3: Issueの自動投稿
  - /issue (POST) : 選んだ repo に Issue 作成

コマンド
  openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes `
  -keyout certs/localhost.key -out certs/localhost.crt `
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost"
"""

from __future__ import annotations

import base64
import hashlib
import html
import os
import secrets
import ssl
import time
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
API_BASE = "https://api.github.com"

SCOPE = "repo"  # プライベートrepo取得/Issue作成に必要

CERT_FILE = os.path.join("certs", "localhost.crt")
KEY_FILE = os.path.join("certs", "localhost.key")

DEFAULT_ISSUE_TITLE = "2026/02/01 OAuth 新規Issue"
DEFAULT_ISSUE_BODY = "自動投稿テストです。"
CLIENT_ID = ""
CLIENT_SECRET = ""

# ===== In-memory state/token (no persistence) =====
SESSION_TTL_SEC = 15 * 60
SESSIONS: Dict[str, Dict[str, str]] = {}  # state -> {"verifier": "...", "ts": "..."}
ACCESS_TOKEN: Optional[str] = None



def require_env(name: str) -> str:
    v = os.environ.get(name, "").strip()
    if not v:
        raise RuntimeError(f"Missing env var: {name}")
    return v


def load_dotenv(path: str = ".env") -> None:
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())

def _now() -> int:
    return int(time.time())

def cleanup_sessions() -> None:
    now = _now()
    dead = []
    for state, info in SESSIONS.items():
        try:
            ts = int(info.get("ts", "0"))
        except ValueError:
            ts = 0
        if now - ts > SESSION_TTL_SEC:
            dead.append(state)
    for state in dead:
        SESSIONS.pop(state, None)


def pkce_generate_verifier() -> str:
    v = secrets.token_urlsafe(64)
    return v[:128]


def pkce_challenge_s256(verifier: str) -> str:
    h = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(h).decode("ascii").rstrip("=")


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


def gh_headers() -> Dict[str, str]:
    if not ACCESS_TOKEN:
        raise RuntimeError("No access token yet")
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {ACCESS_TOKEN}",
        "User-Agent": "oauth-mini/1.0",
    }


class Handler(BaseHTTPRequestHandler):
    # Cookieを取得するための補助関数
    def _get_session_id_from_cookie(self) -> Optional[str]:
        cookie_header = self.headers.get("Cookie", "")
        if "session_id=" in cookie_header:
            # 簡易的なパース
            parts = cookie_header.split("session_id=")
            if len(parts) > 1:
                return parts[1].split(";")[0]
        return None


    #Htmlデータ(ページ)の出力
    def _html(self, status: int, body: str) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        # ブラウザキャッシュに残さない
        self.send_header("Cache-Control", "no-store")
        self.send_header("Pragma", "no-cache")
        self.end_headers()
        self.wfile.write(data)

    #リダイレクト
    def _redirect(self, url: str) -> None:
        self.send_response(302)
        self.send_header("Location", url)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Pragma", "no-cache")
        self.end_headers()

    def _parse_form(self) -> Dict[str, str]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else ""
        q = urllib.parse.parse_qs(raw)
        return {k: (v[0] if v else "") for k, v in q.items()}

    #htmlデータの本体
    def do_GET(self) -> None:

        global ACCESS_TOKEN
        cleanup_sessions()
        u = urllib.parse.urlsplit(self.path)
        path = u.path
        q = urllib.parse.parse_qs(u.query)

        if path == "/login":
            # 1. セッションIDとstateを別々に生成
            session_id = secrets.token_urlsafe(32)
            state = secrets.token_urlsafe(32)
            verifier = pkce_generate_verifier()
            challenge = pkce_challenge_s256(verifier)
            
            # 2. サーバー側では「このセッションIDは、このstateを発行した」と記録
            SESSIONS[session_id] = {
                "state": state,
                "verifier": verifier, 
                "ts": str(_now())
            }
            
            params = {
                "client_id": CLIENT_ID,
                "redirect_uri": REDIRECT_URI,
                "scope": SCOPE,
                "state": state, # GitHubへ送る
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            }

            # 3. ブラウザにセッションIDをCookieとして保存させる
            self.send_response(302)
            self.send_header("Location", AUTHORIZE_URL + "?" + urllib.parse.urlencode(params))
            # HttpOnly, Secure(HTTPS用), SameSite=Lax をつけるのがセキュリティの基本
            self.send_header("Set-Cookie", f"session_id={session_id}; HttpOnly; Secure; SameSite=Lax; Path=/")
            self.end_headers()
            return

        if path == "/callback":
            code = (q.get("code") or [""])[0]
            returned_state = (q.get("state") or [""])[0]
            
            # 1. ブラウザから送られてきたSession IDを確認
            session_id = self._get_session_id_from_cookie()
            info = SESSIONS.get(session_id) if session_id else None
            
            # 2. 厳格なチェック
            # - セッションが存在するか？
            # - そのセッションが発行したstateと、今戻ってきたstateが一致するか？
            if not info or info.get("state") != returned_state:
                self._html(HTTPStatus.FORBIDDEN, "<h1>Invalid session or state (CSRF Protection)</h1>")
                return
            # error handling
            err = (q.get("error") or [""])[0]
            if err:
                desc = (q.get("error_description") or [""])[0]
                self._html(HTTPStatus.BAD_REQUEST, f"<h1>OAuth Error</h1><p>{html.escape(err)} {html.escape(desc)}</p>")
                return

            code = (q.get("code") or [""])[0]
            state = (q.get("state") or [""])[0]
            if not code or not state:
                self._html(HTTPStatus.BAD_REQUEST, "<h1>Missing code/state</h1>")
                return

            info = SESSIONS.get(state)
            if not info:
                self._html(HTTPStatus.FORBIDDEN, "<h1>Invalid state (CSRF suspected)</h1>")
                return

            verifier = info.get("verifier", "")
            if not verifier:
                self._html(HTTPStatus.INTERNAL_SERVER_ERROR, "<h1>PKCE verifier missing</h1>")
                return

            SESSIONS.pop(state, None)

            try:
                #トークン取得のリクエストを送りjsonファイルを取得する
                headers = {"Accept": "application/json", "User-Agent": "oauth-mini/1.0"}
                data = {
                    "client_id": CLIENT_ID,
                    "client_secret": CLIENT_SECRET,
                    "code": code,
                    "redirect_uri": REDIRECT_URI,
                    "code_verifier": verifier,  # PKCE
                }
                r = requests.post(TOKEN_URL, data=data, headers=headers, timeout=15)
                r.raise_for_status()
                token_json = r.json()
                if "error" in token_json:
                    raise RuntimeError(str(token_json))
                ACCESS_TOKEN = token_json.get("access_token")
                self._redirect("/repos")
            except Exception as e:
                self._html(HTTPStatus.INTERNAL_SERVER_ERROR, f"<h1>Token exchange failed</h1><pre>{html.escape(str(e))}</pre>")
            return
            



        if path == "/repos":
            if not ACCESS_TOKEN:
                self._html(HTTPStatus.UNAUTHORIZED, "<h1>No token</h1><p><a href='/login'>Login</a></p>")
                return
            try:
                url = f"{API_BASE}/user/repos"
                params = {
                    "visibility": "all",
                    "per_page": "100",
                    "sort": "updated",
                    "direction": "desc"
                }
                r = requests.get(url, headers=gh_headers(), params=params, timeout=15)
                r.raise_for_status()
                repos = r.json()

                items = []
                for i, repo in enumerate(repos):
                    full_name = str(repo.get("full_name", ""))
                    private = bool(repo.get("private", False))
                    description = str(repo.get("description") or "")
                    updated_at = str(repo.get("updated_at", ""))

                    label = full_name + (" (private)" if private else "")
                    checked = "checked" if i == 0 else ""

                    item_html = (
                        "<label style='display:block; padding:8px; border-bottom:1px solid #ddd; cursor:pointer;'>"
                        f"<input type='radio' name='full_name' value='{html.escape(full_name)}' {checked} required> "
                        f"<strong>{html.escape(label)}</strong><br>"
                        f"<span style='color:#555; font-size: 0.95em;'>"
                        f"{html.escape(description) if description else 'No description'}"
                        f"</span><br>"
                        f"<span style='color:#888; font-size: 0.85em;'>updated: {html.escape(updated_at)}</span>"
                        "</label>"
                    )
                    items.append(item_html)

                body = f"""
<html>
<head>
    <meta charset="utf-8">
    <title>Repositories</title>
</head>
<body style="font-family: sans-serif; margin: 24px;">
    
    <div style="max-width: 700px; margin: 0 auto;">
        
        <h1>Repositories</h1>
        <form method="POST" action="/issue">
            <div style="
                width: 100%; 
                height: 300px;
                overflow-y: auto;
                border: 1px solid #999;
                padding: 4px;
                margin-bottom: 20px;
                background: #fafafa;
                box-sizing: border-box;
            ">
                {"".join(items)}
            </div>

            <div style="margin-bottom: 12px;">
                <label for="title"><strong>Issue Title</strong></label><br>
                <input
                    id="title"
                    name="title"
                    type="text"
                    value="{html.escape(DEFAULT_ISSUE_TITLE)}"
                    required
                    style="width: 100%; padding: 8px; box-sizing: border-box;"
                >
            </div>

            <div style="margin-bottom: 12px;">
                <label for="body"><strong>Issue Body</strong></label><br>
                <textarea
                    id="body"
                    name="body"
                    rows="8"
                    required
                    style="width: 100%; padding: 8px; box-sizing: border-box;"
                >{html.escape(DEFAULT_ISSUE_BODY)}</textarea>
            </div>

            <button type="submit" style="padding: 10px 18px;">Create Issue</button>
        </form>

        <p style="margin-top: 16px;"><a href="/">Back</a></p>
        
    </div>
</body>
</html>
                """
                self._html(HTTPStatus.OK, body)
            except Exception as e:
                self._html(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    f"<h1>Failed to list repos</h1><pre>{html.escape(str(e))}</pre>"
                )

            return
        status = "token acquired" if ACCESS_TOKEN else "no token"
        link = "<a href='/repos'>Go to Repos</a>" if ACCESS_TOKEN else "<a href='/login'>Login with GitHub</a>"
        self._html(HTTPStatus.OK, f"<h1>OAuth</h1><p>{status}</p><p>{link}</p>")



    def do_POST(self) -> None:

        if self.path != "/issue":
            self._html(HTTPStatus.NOT_FOUND, "<h1>Not Found</h1>")
            return

        if not ACCESS_TOKEN:
            self._html(HTTPStatus.UNAUTHORIZED, "<h1>No token</h1><p><a href='/login'>Login</a></p>")
            return

        try:
            form = self._parse_form()
            full_name = form.get("full_name", "").strip()
            title = form.get("title", "").strip()
            body_text = form.get("body", "").strip()

            if not full_name or "/" not in full_name:
                self._html(HTTPStatus.BAD_REQUEST, "<h1>Missing full_name</h1>")
                return

            if not title:
                self._html(HTTPStatus.BAD_REQUEST, "<h1>Missing title</h1><p><a href='/repos'>Back</a></p>")
                return

            if not body_text:
                self._html(HTTPStatus.BAD_REQUEST, "<h1>Missing body</h1><p><a href='/repos'>Back</a></p>")
                return

            owner, repo = full_name.split("/", 1)

            url = f"{API_BASE}/repos/{owner}/{repo}/issues"
            payload = {
                "title": title,
                "body": body_text
            }

            r = requests.post(url, headers=gh_headers(), json=payload, timeout=15)
            r.raise_for_status()
            issue = r.json()

            issue_url = str(issue.get("html_url", ""))
            number = str(issue.get("number", ""))

            result_body = (
                "<h1>Issue created</h1>"
                f"<p><strong>Repository:</strong> {html.escape(full_name)}</p>"
                f"<p><strong>Issue:</strong> #{html.escape(number)}</p>"
                f"<p><strong>Title:</strong> {html.escape(title)}</p>"
                f"<p><a href='{html.escape(issue_url)}' target='_blank' rel='noreferrer'>Open on GitHub</a></p>"
                "<p><a href='/repos'>Back to Repositories</a></p>"
            )
            self._html(HTTPStatus.OK, result_body)

        except Exception as e:
            self._html(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                f"<h1>Issue create failed</h1><pre>{html.escape(str(e))}</pre><p><a href='/repos'>Back</a></p>"
            )




def main() -> None:
    #powershell環境からキーを取得する
    load_dotenv()

    global CLIENT_ID, CLIENT_SECRET
    CLIENT_ID = require_env("CLIENT_ID")
    CLIENT_SECRET = require_env("CLIENT_SECRET")

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