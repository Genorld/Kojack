#!/usr/bin/env python3
"""Kojack website server with a SQLite contact inbox and password-protected admin."""

from __future__ import annotations

import hashlib
import hmac
import getpass
import html
import json
import os
import secrets
import sqlite3
import sys
import time
from contextlib import closing
from datetime import datetime, timezone
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


ROOT = Path(__file__).resolve().parent
DATABASE_PATH = Path(os.environ.get("DATABASE_PATH", ROOT / "messages.sqlite3"))
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
if not ADMIN_PASSWORD and sys.stdin.isatty():
    ADMIN_PASSWORD = getpass.getpass("Weka nenosiri la admin (angalau herufi 12): ")
if len(ADMIN_PASSWORD) < 12:
    raise SystemExit("Provide an admin password with at least 12 characters.")

PASSWORD_SALT = secrets.token_bytes(16)
PASSWORD_HASH = hashlib.scrypt(
    ADMIN_PASSWORD.encode("utf-8"), salt=PASSWORD_SALT, n=2**14, r=8, p=1
)
del ADMIN_PASSWORD

COOKIE_SECURE = os.environ.get("COOKIE_SECURE") == "1"
SESSION_SECONDS = 8 * 60 * 60
MAX_REQUEST_BYTES = 16_384
sessions: dict[str, tuple[float, str]] = {}
login_failures: dict[str, list[float]] = {}
message_requests: dict[str, list[float]] = {}


def initialize_database() -> None:
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not DATABASE_PATH.exists():
        file_descriptor = os.open(DATABASE_PATH, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(file_descriptor)
    with closing(sqlite3.connect(DATABASE_PATH)) as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                name TEXT NOT NULL,
                phone TEXT NOT NULL,
                plan TEXT NOT NULL DEFAULT '',
                message TEXT NOT NULL DEFAULT ''
            )
            """
        )
        db.commit()
    os.chmod(DATABASE_PATH, 0o600)


def rate_limited(store: dict[str, list[float]], key: str, limit: int, period: int) -> bool:
    now = time.monotonic()
    recent = [stamp for stamp in store.get(key, []) if now - stamp < period]
    if len(recent) >= limit:
        store[key] = recent
        return True
    recent.append(now)
    store[key] = recent
    return False


class KojackHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def end_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "same-origin")
        super().end_headers()

    def send_json(self, status: HTTPStatus, value: dict) -> None:
        content = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def send_html(self, status: HTTPStatus, content: str) -> None:
        encoded = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def redirect(self, location: str, cookie: str | None = None) -> None:
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", location)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def session(self) -> tuple[str, str] | None:
        cookie = SimpleCookie()
        cookie.load(self.headers.get("Cookie", ""))
        morsel = cookie.get("kojack_admin")
        if not morsel:
            return None
        token = morsel.value
        session = sessions.get(token)
        if session is None:
            return None
        expires_at, csrf_token = session
        if expires_at <= time.time():
            sessions.pop(token, None)
            return None
        return token, csrf_token

    def read_body(self) -> bytes | None:
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Ombi si sahihi."})
            return None
        if size <= 0 or size > MAX_REQUEST_BYTES:
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Ukubwa wa ombi si sahihi."})
            return None
        return self.rfile.read(size)

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path in ("/admin", "/admin.html"):
            self.admin_page()
            return
        if path == "/admin/login":
            self.login_page()
            return
        if path not in ("/", "/index.html", "/favicon.svg", "/kojack-about.jpeg"):
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        if path == "/":
            self.path = "/index.html"
        super().do_GET()

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        if path == "/api/messages":
            self.create_message()
        elif path == "/admin/login":
            self.login()
        elif path == "/admin/logout":
            self.logout()
        else:
            self.send_json(HTTPStatus.NOT_FOUND, {"error": "Ukurasa haujapatikana."})

    def create_message(self) -> None:
        origin = self.headers.get("Origin")
        if origin and urlsplit(origin).netloc.casefold() != self.headers.get("Host", "").casefold():
            self.send_json(HTTPStatus.FORBIDDEN, {"error": "Ombi halikubaliki."})
            return
        if self.headers.get_content_type() != "application/json":
            self.send_json(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": "Tuma ujumbe kwa JSON."})
            return
        if rate_limited(message_requests, self.client_address[0], 10, 3600):
            self.send_json(HTTPStatus.TOO_MANY_REQUESTS, {"error": "Umetuma maombi mengi. Jaribu tena baadaye."})
            return
        raw_body = self.read_body()
        if raw_body is None:
            return
        try:
            payload = json.loads(raw_body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Ujumbe haukusomeka."})
            return
        if not isinstance(payload, dict):
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Ombi si sahihi."})
            return

        fields = {}
        limits = {"name": 120, "phone": 40, "plan": 80, "message": 5000}
        for field, limit in limits.items():
            value = payload.get(field, "")
            if not isinstance(value, str) or len(value.strip()) > limit:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Taarifa ulizoweka si sahihi."})
                return
            fields[field] = value.strip()
        if not fields["name"] or not fields["phone"]:
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Jina na namba ya simu vinahitajika."})
            return

        created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with closing(sqlite3.connect(DATABASE_PATH)) as db:
            cursor = db.execute(
                "INSERT INTO messages (created_at, name, phone, plan, message) VALUES (?, ?, ?, ?, ?)",
                (created_at, fields["name"], fields["phone"], fields["plan"], fields["message"]),
            )
            db.commit()
            message_id = cursor.lastrowid
        self.send_json(HTTPStatus.CREATED, {"id": message_id})

    def login_page(self, error: bool = False) -> None:
        if self.session():
            self.redirect("/admin")
            return
        notice = '<p class="error">Nenosiri si sahihi au umejaribu mara nyingi.</p>' if error else ""
        self.send_html(
            HTTPStatus.OK,
            f"""<!doctype html><html lang="sw"><meta charset="utf-8">
            <meta name="viewport" content="width=device-width,initial-scale=1">
            <title>Kuingia admin — Kojack</title><style>
            body{{font:16px system-ui;background:#f7f7f3;color:#17191b;margin:0;min-height:100vh;display:grid;place-items:center}}
            main{{width:min(380px,calc(100% - 40px));background:white;padding:30px;border-radius:20px;box-shadow:0 12px 40px #17191b12}}
            h1{{font-size:25px;margin-top:0}}label{{display:block;font-size:14px;font-weight:600;margin:18px 0 7px}}
            input,button{{font:inherit;width:100%;padding:13px;border-radius:10px}}input{{border:1px solid #ddd}}
            button{{border:0;background:#17191b;color:white;font-weight:700;margin-top:16px;cursor:pointer}}
            .error{{color:#a12727}}a{{color:#555}}</style><main><h1>Ingia admin</h1>{notice}
            <form method="post" action="/admin/login"><label for="password">Nenosiri la admin</label>
            <input id="password" name="password" type="password" autocomplete="current-password" required>
            <button type="submit">Ingia</button></form></main></html>""",
        )

    def login(self) -> None:
        ip = self.client_address[0]
        if rate_limited(login_failures, ip, 5, 600):
            self.send_html(HTTPStatus.TOO_MANY_REQUESTS, "Umejaribu mara nyingi. Jaribu tena baada ya dakika 10.")
            return
        raw_body = self.read_body()
        if raw_body is None:
            return
        form = parse_qs(raw_body.decode("utf-8", errors="replace"))
        password = form.get("password", [""])[0]
        candidate = hashlib.scrypt(password.encode("utf-8"), salt=PASSWORD_SALT, n=2**14, r=8, p=1)
        if not hmac.compare_digest(candidate, PASSWORD_HASH):
            self.login_page(error=True)
            return

        login_failures.pop(ip, None)
        token = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        sessions[token] = (time.time() + SESSION_SECONDS, csrf_token)
        secure = "; Secure" if COOKIE_SECURE else ""
        cookie = f"kojack_admin={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_SECONDS}{secure}"
        self.redirect("/admin", cookie)

    def admin_page(self) -> None:
        session = self.session()
        if session is None:
            self.redirect("/admin/login")
            return
        _, csrf_token = session
        with closing(sqlite3.connect(DATABASE_PATH)) as db:
            db.row_factory = sqlite3.Row
            messages = db.execute(
                "SELECT id, created_at, name, phone, plan, message FROM messages ORDER BY id DESC LIMIT 500"
            ).fetchall()
        rows = "".join(
            "<tr>"
            f"<td>{html.escape(row['created_at'])}</td>"
            f"<td>{html.escape(row['name'])}</td>"
            f"<td>{html.escape(row['phone'])}</td>"
            f"<td>{html.escape(row['plan'] or '—')}</td>"
            f"<td class=\"message\">{html.escape(row['message'] or '—')}</td>"
            "</tr>"
            for row in messages
        )
        if not rows:
            rows = '<tr><td colspan="5">Bado hakuna ujumbe.</td></tr>'
        self.send_html(
            HTTPStatus.OK,
            f"""<!doctype html><html lang="sw"><meta charset="utf-8">
            <meta name="viewport" content="width=device-width,initial-scale=1">
            <title>Ujumbe wa wateja — Kojack</title><style>
            *{{box-sizing:border-box}}body{{font:15px system-ui;background:#f7f7f3;color:#17191b;margin:0}}
            header{{display:flex;justify-content:space-between;align-items:center;padding:20px max(20px,calc((100% - 1200px)/2));background:white}}
            h1{{font-size:24px;margin:0}}button{{font:inherit;border:0;border-radius:999px;background:#17191b;color:white;padding:11px 18px;font-weight:700;cursor:pointer}}
            main{{max-width:1200px;margin:32px auto;padding:0 20px}}.count{{color:#666}}
            .table-wrap{{overflow:auto;background:white;border-radius:16px;border:1px solid #e8e8e5}}
            table{{width:100%;border-collapse:collapse;min-width:800px}}th,td{{padding:14px 16px;text-align:left;vertical-align:top;border-bottom:1px solid #eee}}
            th{{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:#686b67}}td{{max-width:360px}}
            .message{{white-space:pre-wrap;overflow-wrap:anywhere}}form{{margin:0}}</style>
            <header><h1>Ujumbe wa wateja wa Kojack</h1><form method="post" action="/admin/logout">
            <input type="hidden" name="csrf" value="{html.escape(csrf_token, quote=True)}"><button type="submit">Toka</button></form></header>
            <main><p class="count">Ujumbe {len(messages)} wa hivi karibuni (hadi 500)</p>
            <div class="table-wrap"><table><thead><tr><th>Tarehe (UTC)</th><th>Jina</th><th>Simu</th><th>Mpango</th><th>Ujumbe</th></tr></thead>
            <tbody>{rows}</tbody></table></div></main></html>""",
        )

    def logout(self) -> None:
        session = self.session()
        if session is None:
            self.redirect("/admin/login")
            return
        token, csrf_token = session
        raw_body = self.read_body()
        if raw_body is None:
            return
        form = parse_qs(raw_body.decode("utf-8", errors="replace"))
        submitted_csrf = form.get("csrf", [""])[0]
        if not hmac.compare_digest(submitted_csrf, csrf_token):
            self.send_html(HTTPStatus.FORBIDDEN, "Ombi halikubaliki.")
            return
        sessions.pop(token, None)
        secure = "; Secure" if COOKIE_SECURE else ""
        cookie = f"kojack_admin=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{secure}"
        self.redirect("/admin/login", cookie)


def main() -> None:
    initialize_database()
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    if host not in ("127.0.0.1", "localhost", "::1") and not COOKIE_SECURE:
        raise SystemExit("Set COOKIE_SECURE=1 when exposing the app behind HTTPS.")
    server = ThreadingHTTPServer((host, port), KojackHandler)
    print(f"Kojack server running at http://{host}:{port} (admin: /admin)")
    server.serve_forever()


if __name__ == "__main__":
    main()
