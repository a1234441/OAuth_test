from __future__ import annotations

import os
import ssl
from http.server import ThreadingHTTPServer

from github_oauth_app import GitHubOAuthHandler, configure_oauth
from http_server_base import build_ssl_context
from urllib.parse import urlparse 
# main.py (改良案のイメージ)



DEFAULT_BASE_URL = "https://localhost:8443"

CERT_FILE = os.path.join("certs", "localhost.crt")
KEY_FILE = os.path.join("certs", "localhost.key")


def require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"Missing env var: {name}")
    return value


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



def main() -> None:
    #環境変数の読み込みと
    load_dotenv()
    client_id = require_env("CLIENT_ID")
    client_secret = require_env("CLIENT_SECRET")

    base_url = os.environ.get("BASE_URL", DEFAULT_BASE_URL)
    parsed_url = urlparse(base_url)
    host = parsed_url.hostname or "localhost"
    # ポート番号（URLに含まれていればそれを使い、なければプロトコルから推測）
    port = parsed_url.port
    if parsed_url.port:
        port = parsed_url.port
    else:
        # URLにポートがない場合、443/80を狙わず、安全な「4001」などをデフォルトにする
        print(f"Warning: No port in BASE_URL.")
        raise 
    configure_oauth(
        base_url=base_url,
        client_id=client_id,
        client_secret=client_secret,
    )

    # サーバー起動（分解した host と port を使用）
    httpd = ThreadingHTTPServer((host, port), GitHubOAuthHandler)
    ctx_=build_ssl_context(CERT_FILE,KEY_FILE)
    httpd.socket = ctx_.wrap_socket(httpd.socket,server_side=True)
    print(f"Serving on {base_url}")
    print("Open the URL in your browser -> click 'Login with GitHub'.")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()