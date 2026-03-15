from __future__ import annotations

import base64
import hashlib
import html
import secrets
import time
import urllib.parse
from http import HTTPStatus
from typing import Dict, Optional
import requests
from http_server_base import AppHandlerBase
from datetime import datetime

# ===== GitHub OAuth / API 設定 =====
AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
TOKEN_URL = "https://github.com/login/oauth/access_token"
API_BASE = "https://api.github.com"
SCOPE = "repo"  # private repo 取得 / issue 作成を含む

# main.py から設定される
BASE_URL = ""
REDIRECT_URI = ""
CLIENT_ID = ""
CLIENT_SECRET = ""

# ===== 状態管理 =====
SESSION_TTL_SEC = 15 * 60
SESSIONS: Dict[str, Dict[str, str]] = {}
ACCESS_TOKEN: Optional[str] = None


def configure_oauth(base_url: str, client_id: str, client_secret: str) -> None:
    global BASE_URL, REDIRECT_URI, CLIENT_ID, CLIENT_SECRET
    BASE_URL = base_url
    REDIRECT_URI = f"{BASE_URL}/callback"
    CLIENT_ID = client_id
    CLIENT_SECRET = client_secret


def _now() -> int:
    return int(time.time())


def cleanup_sessions() -> None:
    now = _now()
    dead = []
    for session_id, info in SESSIONS.items():
        try:
            ts = int(info.get("ts", "0"))
        except ValueError:
            ts = 0
        if now - ts > SESSION_TTL_SEC:
            dead.append(session_id)
    for session_id in dead:
        SESSIONS.pop(session_id, None)


def pkce_generate_verifier() -> str:
    verifier = secrets.token_urlsafe(64)
    return verifier[:128]


def pkce_challenge_s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

#APIをたたく時のヘッダー
def gh_headers() -> Dict[str, str]:
    if not ACCESS_TOKEN:
        raise RuntimeError("No access token yet")
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {ACCESS_TOKEN}",
        "User-Agent": "oauth-mini/1.0",
    }

#HTMLフォームから送られてきたデータを読む
def parse_form(handler: AppHandlerBase) -> Dict[str, str]:
    length = int(handler.headers.get("Content-Length", "0") or "0")
    raw = handler.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else ""
    q = urllib.parse.parse_qs(raw)
    #辞書にして返す
    return {k: (v[0] if v else "") for k, v in q.items()}


class GitHubOAuthHandler(AppHandlerBase):
    def do_get_(self) -> None:
        global ACCESS_TOKEN
        cleanup_sessions()

        #urlを本体とクエリで分割する
        u = urllib.parse.urlsplit(self.path)
        path = u.path
        q = urllib.parse.parse_qs(u.query)

        # ===== /login =====
        if path == "/login":
            session_id = secrets.token_urlsafe(32)
            state = secrets.token_urlsafe(32)
            #ランダムな整数を生成する
            verifier = pkce_generate_verifier()
            challenge = pkce_challenge_s256(verifier)

            # session_id をキーとして保存する
            SESSIONS[session_id] = {"state": state,"verifier": verifier,"ts": str(_now()),}

            params = {
                "client_id": CLIENT_ID,
                "redirect_uri": REDIRECT_URI,
                "scope": SCOPE,
                "state": state,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            }

            self.send_response(302)
            self.send_header("Location", AUTHORIZE_URL + "?" + urllib.parse.urlencode(params))
            self.send_header("Set-Cookie",f"session_id={session_id}; HttpOnly; Secure; SameSite=Lax; Path=/")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Pragma", "no-cache")
            self.end_headers()
            return

        # ===== /callback =====
        if path == "/callback":
            err = (q.get("error") or [""])[0]
            if err:
                desc = (q.get("error_description") or [""])[0]
                self._html(
                    HTTPStatus.BAD_REQUEST,
                    f"<h1>OAuth Error</h1><p>{html.escape(err)} {html.escape(desc)}</p>",
                )
                return

            code = (q.get("code") or [""])[0]
            returned_state = (q.get("state") or [""])[0]

            if not code or not returned_state:
                self._html(HTTPStatus.BAD_REQUEST, "<h1>Missing code/state</h1>")
                return

            session_id = self._get_session_id_from_cookie()
            info = SESSIONS.get(session_id) if session_id else None

            # ここを session_id ベースに統一して修正
            if not info or info.get("state") != returned_state:
                self._html(
                    HTTPStatus.FORBIDDEN,
                    "<h1>Invalid session or state (CSRF Protection)</h1>",
                )
                return

            verifier = info.get("verifier", "")
            if not verifier:
                self._html(HTTPStatus.INTERNAL_SERVER_ERROR, "<h1>PKCE verifier missing</h1>")
                return

            # state の再利用防止
            SESSIONS.pop(session_id, None)

            try:
                headers = {
                    "Accept": "application/json",
                    "User-Agent": "oauth-mini/1.0",
                }
                data = {
                    "client_id": CLIENT_ID,
                    "client_secret": CLIENT_SECRET,
                    "code": code,
                    "redirect_uri": REDIRECT_URI,
                    "code_verifier": verifier,
                }

                r = requests.post(TOKEN_URL, data=data, headers=headers, timeout=15)
                r.raise_for_status()
                token_json = r.json()

                if "error" in token_json:
                    raise RuntimeError(str(token_json))

                ACCESS_TOKEN = token_json.get("access_token")
                if not ACCESS_TOKEN:
                    raise RuntimeError("access_token not found in token response")

                self._redirect("/repos")
            except Exception as e:
                self._html(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    f"<h1>Token exchange failed</h1><pre>{html.escape(str(e))}</pre>",
                )
            return

        # ===== /repos =====
        if path == "/repos":
            if not ACCESS_TOKEN:
                self._html(
                    HTTPStatus.UNAUTHORIZED,
                    "<h1>No token</h1><p><a href='/login'>Login</a></p>",
                )
                return

            try:
                url = f"{API_BASE}/user/repos"
                params = {
                    "visibility": "all",
                    "per_page": "100",
                    "sort": "updated",
                    "direction": "desc",
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
                        f"<span style='color:#555; font-size:0.95em;'>"
                        f"{html.escape(description) if description else 'No description'}"
                        f"</span><br>"
                        f"<span style='color:#888; font-size:0.85em;'>updated: {html.escape(updated_at)}</span>"
                        "</label>"
                    )
                    items.append(item_html)


                today_str = datetime.now().strftime("%Y/%m/%d")
                default_title = f"{today_str} OAuth 新規Issue"
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
                                width: 700px;
                                max-width: 100%;
                                height: 300px;
                                overflow-y: auto;
                                border: 1px solid #999;
                                padding: 4px;
                                margin-bottom: 20px;
                                background: #fafafa;
                                box-sizing: border-box; /* パディングを含めた幅にするための追加 */
                            ">
                                {"".join(items)}
                            </div>

                            <div style="margin-bottom: 12px;">
                                <label for="title"><strong>Issue Title</strong></label><br>
                                <input
                                    id="title"
                                    name="title"
                                    type="text"
                                    value="{default_title} 新規Issue"
                                    required
                                    style="width: 100%; box-sizing: border-box; padding: 8px;"
                                >
                            </div>

                            <div style="margin-bottom: 12px;">
                                <label for="body"><strong>Issue Body</strong></label><br>
                                <textarea
                                    id="body"
                                    name="body"
                                    rows="8"
                                    required
                                    style="width: 100%; box-sizing: border-box; padding: 8px;"
                                >自動投稿テストです。</textarea>
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
                    f"<h1>Failed to list repos</h1><pre>{html.escape(str(e))}</pre>",
                )
            return

        # ===== / =====
        status = "token acquired" if ACCESS_TOKEN else "no token"
        link = "<a href='/repos'>Go to Repos</a>" if ACCESS_TOKEN else "<a href='/login'>Login with GitHub</a>"
        self._html(HTTPStatus.OK, f"<h1>OAuth</h1><p>{status}</p><p>{link}</p>")



    def do_post_(self) -> None:
        if self.path != "/issue":
            self._html(HTTPStatus.NOT_FOUND, "<h1>Not Found</h1>")
            return

        if not ACCESS_TOKEN:
            self._html(
                HTTPStatus.UNAUTHORIZED,
                "<h1>No token</h1><p><a href='/login'>Login</a></p>",
            )
            return

        try:
            form = parse_form(self)
            full_name = form.get("full_name", "").strip()
            title = form.get("title", "").strip()
            body_text = form.get("body", "").strip()
            if not full_name or "/" not in full_name:
                self._html(HTTPStatus.BAD_REQUEST, "<h1>Missing full_name</h1>")
                return

            if not title:
                self._html(
                    HTTPStatus.BAD_REQUEST,
                    "<h1>Missing title</h1><p><a href='/repos'>Back</a></p>",
                )
                return

            if not body_text:
                self._html(
                    HTTPStatus.BAD_REQUEST,
                    "<h1>Missing body</h1><p><a href='/repos'>Back</a></p>",
                )
                return

            owner, repo = full_name.split("/", 1)
            url = f"{API_BASE}/repos/{owner}/{repo}/issues"
            payload = {
                "title": title,
                "body": body_text,
            }
            #issueを送信する
            #送信に成功するとその内容がjsonで返ってくる
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
                f"<h1>Issue create failed</h1><pre>{html.escape(str(e))}</pre>"
                "<p><a href='/repos'>Back</a></p>",
            )