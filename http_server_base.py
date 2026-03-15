from __future__ import annotations

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from typing import Optional
import os
import ssl


def build_ssl_context(cert_file: str, key_file: str) -> ssl.SSLContext:
    if not (os.path.exists(cert_file) and os.path.exists(key_file)):
        raise RuntimeError(
            "TLS certificate not found.\n"
            f"Expected:\n  {cert_file}\n  {key_file}\n"
        )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
    return ctx

class AppHandlerBase(BaseHTTPRequestHandler):
    # Cookie から session_id を取り出す
    def _get_session_id_from_cookie(self) -> Optional[str]:
        cookie_header = self.headers.get("Cookie", "")
        if not cookie_header:
            return None
        for part in cookie_header.split(";"):
            part = part.strip()
            if part.startswith("session_id="):
                return part[len("session_id="):]

        return None

    # HTML を返す
    def _html(self, status: int, body: str) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Pragma", "no-cache")
        self.end_headers()
        self.wfile.write(data)

    # リダイレクト
    def _redirect(self, url: str) -> None:
        self.send_response(302)
        self.send_header("Location", url)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Pragma", "no-cache")
        self.end_headers()

    # GET の骨格
    def do_GET(self) -> None:
        self.do_get_()

    # POST の骨格
    def do_POST(self) -> None:
        self.do_post_()

    # 実際の GET 処理は派生側で実装
    def do_get_(self) -> None:
        self._html(HTTPStatus.NOT_FOUND, "<h1>Not Found</h1>")

    # 実際の POST 処理は派生側で実装
    def do_post_(self) -> None:
        self._html(HTTPStatus.NOT_FOUND, "<h1>Not Found</h1>")