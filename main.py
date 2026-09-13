import os
import re
import json
import time
import secrets
import hashlib
import hmac
import urllib.request
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie

PORT = int(os.getenv("PORT", "10000"))

SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_KEY = os.getenv("SUPABASE_SECRET_KEY", "")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
REPORT_PASSWORD = os.getenv("REPORT_PASSWORD", "")

APP_NAME = "سامانه غدیر"

SESSIONS = {}
LOGIN_ATTEMPTS = {}

SESSION_TTL = 2 * 60 * 60
MAX_REPORT_LENGTH = 10000


# =========================
# امنیت پایه
# =========================

def clean_expired_sessions():
    now = time.time()
    for sid in list(SESSIONS):
        if now - SESSIONS[sid]["created"] > SESSION_TTL:
            del SESSIONS[sid]


def get_session(handler):
    clean_expired_sessions()

    cookie = SimpleCookie()
    cookie.load(handler.headers.get("Cookie", ""))

    sid = cookie["session"].value if "session" in cookie else None

    if not sid or sid not in SESSIONS:
        return None

    session = SESSIONS[sid]

    if time.time() - session["created"] > SESSION_TTL:
        del SESSIONS[sid]
        return None

    return session


def new_session():
    sid = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)

    SESSIONS[sid] = {
        "created": time.time(),
        "csrf": csrf,
        "admin": False
    }

    return sid


def client_ip(handler):
    forwarded = handler.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()

    return handler.client_address[0]


def login_allowed(ip):
    now = time.time()

    attempts = LOGIN_ATTEMPTS.get(ip, [])

    attempts = [
        t for t in attempts
        if now - t < 600
    ]

    LOGIN_ATTEMPTS[ip] = attempts

    return len(attempts) < 5


def register_login_attempt(ip):
    LOGIN_ATTEMPTS.setdefault(ip, []).append(time.time())


def safe_compare(a, b):
    return hmac.compare_digest(
        str(a).encode(),
        str(b).encode()
    )


# =========================
# Supabase
# =========================

def supabase_request(method, path, data=None, query=""):
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise RuntimeError("Supabase environment variables are missing")

    url = SUPABASE_URL + path

    if query:
        url += "?" + query

    body = None

    if data is not None:
        body = json.dumps(data).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=body,
        method=method
    )

    req.add_header("apikey", SUPABASE_KEY)
    req.add_header("Authorization", "Bearer " + SUPABASE_KEY)
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")

    if method == "POST":
        req.add_header("Prefer", "return=representation")

    with urllib.request.urlopen(req, timeout=15) as response:
        raw = response.read().decode("utf-8")

        if not raw:
            return None

        return json.loads(raw)


def create_report(text):
    tracking_code = (
        "GHD-" +
        secrets.token_hex(5).upper()
    )

    data = {
        "report": text,
        "tracking_code": tracking_code,
        "status": "جدید"
    }

    result = supabase_request(
        "POST",
        "/rest/v1/reports",
        data
    )

    return tracking_code


def get_reports():
    query = urllib.parse.urlencode({
        "select": "*",
        "order": "created_at.desc"
    })

    return supabase_request(
        "GET",
        "/rest/v1/reports",
        query=query
    ) or []


def get_report(code):
    query = urllib.parse.urlencode({
        "select": "*",
        "tracking_code": "eq." + code
    })

    result = supabase_request(
        "GET",
        "/rest/v1/reports",
        query=query
    ) or []

    return result[0] if result else None


def update_status(report_id, status):
    query = urllib.parse.urlencode({
        "id": "eq." + str(report_id)
    })

    supabase_request(
        "PATCH",
        "/rest/v1/reports",
        {"status": status},
        query=query
    )


def delete_report(report_id):
    query = urllib.parse.urlencode({
        "id": "eq." + str(report_id)
    })

    supabase_request(
        "DELETE",
        "/rest/v1/reports",
        query=query
    )


# =========================
# HTML
# =========================

CSS = r"""
* {
    box-sizing: border-box;
}

body {
    margin: 0;
    font-family: Tahoma, Arial, sans-serif;
    background:
        radial-gradient(circle at top right, #172554, transparent 35%),
        radial-gradient(circle at bottom left, #1e1b4b, transparent 40%),
        #020617;
    color: #f8fafc;
    min-height: 100vh;
}

a {
    text-decoration: none;
    color: inherit;
}

.container {
    width: min(1100px, 92%);
    margin: auto;
}

.nav {
    padding: 20px 0;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.logo {
    font-size: 24px;
    font-weight: bold;
}

.logo span {
    color: #38bdf8;
}

.nav a {
    padding: 10px 15px;
    border-radius: 12px;
    background: rgba(255,255,255,.06);
}

.hero {
    padding: 80px 0 60px;
    text-align: center;
}

.shield {
    width: 100px;
    height: 100px;
    margin: auto;
    border-radius: 30px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 48px;
    background: linear-gradient(135deg,#2563eb,#7c3aed);
    box-shadow:
        0 0 35px rgba(59,130,246,.5),
        inset 0 0 25px rgba(255,255,255,.15);
}

h1 {
    font-size: clamp(35px,7vw,70px);
    margin: 25px 0 10px;
}

.subtitle {
    color: #94a3b8;
    font-size: 18px;
    line-height: 1.9;
}

.buttons {
    display: flex;
    justify-content: center;
    gap: 14px;
    flex-wrap: wrap;
    margin-top: 35px;
}

.btn {
    border: 0;
    cursor: pointer;
    display: inline-block;
    padding: 15px 25px;
    border-radius: 15px;
    color: white;
    font-size: 16px;
    font-weight: bold;
    background: linear-gradient(135deg,#2563eb,#7c3aed);
    box-shadow: 0 10px 30px rgba(37,99,235,.25);
}

.btn.secondary {
    background: rgba(255,255,255,.07);
    box-shadow: none;
}

.card {
    background: rgba(15,23,42,.72);
    border: 1px solid rgba(148,163,184,.13);
    border-radius: 24px;
    padding: 25px;
    margin: 20px 0;
    box-shadow: 0 20px 50px rgba(0,0,0,.25);
    backdrop-filter: blur(15px);
}

input,
textarea,
select {
    width: 100%;
    border: 1px solid #334155;
    background: #020617;
    color: white;
    border-radius: 13px;
    padding: 14px;
    margin: 8px 0 15px;
    font-size: 16px;
}

textarea {
    min-height: 220px;
    resize: vertical;
}

label {
    color: #cbd5e1;
    font-weight: bold;
}

.center {
    text-align: center;
}

.code {
    font-size: 27px;
    letter-spacing: 3px;
    color: #38bdf8;
    font-weight: bold;
    margin: 20px 0;
}

.report {
    white-space: pre-wrap;
    line-height: 1.9;
    background: #020617;
    border-radius: 15px;
    padding: 18px;
    margin-top: 15px;
}

.status {
    display: inline-block;
    padding: 7px 13px;
    border-radius: 20px;
    background: rgba(56,189,248,.15);
    color: #38bdf8;
}

.danger {
    background: linear-gradient(135deg,#dc2626,#991b1b);
}

.small {
    color: #64748b;
    font-size: 13px;
}

footer {
    text-align: center;
    color: #64748b;
    padding: 50px 0;
}

@media(max-width:600px) {
    .hero {
        padding-top: 45px;
    }

    .card {
        padding: 18px;
    }
}
"""


def page(title, body, session=None):
    csrf = ""

    if session:
        csrf = session["csrf"]

    return f"""<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="description" content="سامانه غدیر">
<meta http-equiv="Content-Security-Policy"
content="default-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; base-uri 'self'; frame-ancestors 'none'">
<meta name="referrer" content="no-referrer">
<title>{title} | {APP_NAME}</title>
<style>{CSS}</style>
</head>

<body>

<div class="container">

<div class="nav">
    <div class="logo">🛡️ <span>{APP_NAME}</span></div>

    <a href="/">خانه</a>
</div>

{body}

<footer>
    {APP_NAME}
</footer>

</div>

</body>
</html>
"""


# =========================
# صفحات
# =========================

def home_page():
    body = """
<section class="hero">

<div class="shield">🛡️</div>

<h1>سامانه غدیر</h1>

<div class="subtitle">
سامانه ثبت و پیگیری گزارش‌ها
<br>
ساده، آنلاین و قابل استفاده در دستگاه‌های مختلف
</div>

<div class="buttons">

<a class="btn" href="/report">
ثبت گزارش
</a>

<a class="btn secondary" href="/track">
پیگیری گزارش
</a>

<a class="btn secondary" href="/admin">
مدیریت
</a>

</div>

</section>

<div class="card center">

<h2>🔐 گزارش خود را ثبت کنید</h2>

<p class="subtitle">
پس از ثبت گزارش، یک کد پیگیری دریافت می‌کنید.
</p>

</div>
"""

    return page(APP_NAME, body)


def report_page():
    body = """
<div class="card">

<h2>📝 ثبت گزارش</h2>

<p class="subtitle">
گزارش خود را وارد کنید.
</p>

<form method="POST" action="/submit">

<label>رمز ثبت گزارش</label>
<input
type="password"
name="password"
required
autocomplete="off"
>

<label>متن گزارش</label>

<textarea
name="report"
maxlength="10000"
required
placeholder="متن گزارش را اینجا وارد کنید..."
></textarea>

<button class="btn" type="submit">
ثبت گزارش
</button>

</form>

</div>
"""

    return page("ثبت گزارش", body)


def track_page(result=None):
    extra = ""

    if result:
        if result.get("found"):
            r = result["report"]

            extra = f"""
<div class="card">

<h2>✅ گزارش پیدا شد</h2>

<p>
وضعیت:
<span class="status">
{r.get("status", "نامشخص")}
</span>
</p>

<p class="small">
زمان ثبت:
{r.get("created_at", "نامشخص")}
</p>

<div class="report">
{r.get("report", "")}
</div>

</div>
"""
        else:
            extra = """
<div class="card center">
<h3>❌ گزارشی با این کد پیدا نشد.</h3>
</div>
"""

    body = f"""
<div class="card">

<h2>🔎 پیگیری گزارش</h2>

<form method="GET" action="/track">

<label>کد پیگیری</label>

<input
name="code"
placeholder="مثلاً GHD-ABC123..."
required
>

<button class="btn">
پیگیری
</button>

</form>

</div>

{extra}
"""

    return page("پیگیری گزارش", body)


def login_page(error=""):
    error_html = ""

    if error:
        error_html = f"""
<div class="card">
<p style="color:#f87171">{error}</p>
</div>
"""

    body = f"""
{error_html}

<div class="card">

<h2>🔐 ورود مدیریت</h2>

<form method="POST" action="/login">

<label>رمز عبور</label>

<input
type="password"
name="password"
required
autocomplete="off"
>

<button class="btn">
ورود
</button>

</form>

</div>
"""

    return page("ورود مدیریت", body)


def admin_page(session):
    csrf = session["csrf"]

    reports = get_reports()

    cards = ""

    for r in reports:
        rid = str(r.get("id", ""))

        report_text = r.get("report", "")
        status = r.get("status", "جدید")
        code = r.get("tracking_code", "بدون کد")

        cards += f"""
<div class="card">

<div>
<strong>کد پیگیری:</strong>

<div class="code">
{code}
</div>
</div>

<p>
<span class="status">{status}</span>
</p>

<div class="report">
{report_text}
</div>

<p class="small">
{r.get("created_at", "")}
</p>

<form method="POST" action="/status">

<input type="hidden" name="csrf" value="{csrf}">
<input type="hidden" name="id" value="{rid}">

<select name="status">

<option value="جدید">جدید</option>
<option value="در حال بررسی">در حال بررسی</option>
<option value="بررسی شد">بررسی شد</option>
<option value="بسته شد">بسته شد</option>

</select>

<button class="btn">
تغییر وضعیت
</button>

</form>

<form method="POST" action="/delete"
onsubmit="return confirm('این گزارش حذف شود؟');">

<input type="hidden" name="csrf" value="{csrf}">
<input type="hidden" name="id" value="{rid}">

<button class="btn danger">
حذف گزارش
</button>

</form>

</div>
"""

    if not cards:
        cards = """
<div class="card center">
<h3>هنوز گزارشی ثبت نشده است.</h3>
</div>
"""

    body = f"""
<div class="card">

<h2>🛡️ پنل مدیریت</h2>

<p>
تعداد گزارش‌ها:
<strong>{len(reports)}</strong>
</p>

<form method="GET" action="/logout">

<button class="btn secondary">
خروج
</button>

</form>

</div>

{cards}
"""

    return page("پنل مدیریت", body, session)


def success_page(code):
    body = f"""
<div class="card center">

<h2>✅ گزارش با موفقیت ثبت شد</h2>

<p class="subtitle">
کد پیگیری خود را حتماً نگه دارید.
</p>

<div class="code">
{code}
</div>

<a class="btn" href="/track?code={urllib.parse.quote(code)}">
پیگیری گزارش
</a>

</div>
"""

    return page("گزارش ثبت شد", body)


# =========================
# HTTP Handler
# =========================

class Handler(BaseHTTPRequestHandler):

    def send_html(self, html, status=200, cookie=None):
        data = html.encode("utf-8")

        self.send_response(status)

        self.send_header(
            "Content-Type",
            "text/html; charset=utf-8"
        )

        self.send_header(
            "Content-Length",
            str(len(data))
        )

        self.send_header(
            "X-Content-Type-Options",
            "nosniff"
        )

        self.send_header(
            "X-Frame-Options",
            "DENY"
        )

        self.send_header(
            "Referrer-Policy",
            "no-referrer"
        )

        self.send_header(
            "Permissions-Policy",
            "geolocation=(), microphone=(), camera=()"
        )

        self.send_header(
            "Cache-Control",
            "no-store"
        )

        if cookie:
            self.send_header(
                "Set-Cookie",
                cookie
            )

        self.end_headers()

        self.wfile.write(data)

    def redirect(self, location):
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def read_form(self):
        length = int(
            self.headers.get("Content-Length", "0")
        )

        if length > 12000:
            return {}

        raw = self.rfile.read(length).decode(
            "utf-8",
            errors="replace"
        )

        return urllib.parse.parse_qs(
            raw,
            keep_blank_values=True
        )

    def get_value(self, form, key):
        values = form.get(key, [])
        return values[0] if values else ""

    def do_GET(self):

        try:

            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path

            if path == "/":
                self.send_html(home_page())
                return

            if path == "/report":
                self.send_html(report_page())
                return

            if path == "/track":

                params = urllib.parse.parse_qs(
                    parsed.query
                )

                code = params.get(
                    "code",
                    [""]
                )[0].strip().upper()

                result = None

                if code:
                    report = get_report(code)

                    result = {
                        "found": report is not None,
                        "report": report
                    }

                self.send_html(
                    track_page(result)
                )

                return

            if path == "/admin":

                session = get_session(self)

                if not session or not session.get("admin"):
                    self.send_html(
                        login_page()
                    )
                    return

                self.send_html(
                    admin_page(session)
                )

                return

            if path == "/logout":

                session = get_session(self)

                if session:
                    for sid, value in list(SESSIONS.items()):
                        if value is session:
                            del SESSIONS[sid]

                cookie = (
                    "session=deleted; "
                    "Path=/; "
                    "Max-Age=0; "
                    "HttpOnly; "
                    "Secure; "
                    "SameSite=Strict"
                )

                self.send_html(
                    login_page("با موفقیت خارج شدید."),
                    cookie=cookie
                )

                return

            self.send_html(
                page(
                    "404",
                    """
<div class="card center">
<h2>404</h2>
<p>صفحه پیدا نشد.</p>
<a class="btn" href="/">بازگشت</a>
</div>
"""
                ),
                404
            )

        except Exception as e:

            print("GET ERROR:", repr(e))

            self.send_html(
                page(
                    "خطا",
                    """
<div class="card center">
<h2>خطایی رخ داد</h2>
<a class="btn" href="/">بازگشت</a>
</div>
"""
                ),
                500
            )

    def do_POST(self):

        try:

            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path

            form = self.read_form()

            # =========================
            # ثبت گزارش
            # =========================

            if path == "/submit":

                password = self.get_value(
                    form,
                    "password"
                )

                report = self.get_value(
                    form,
                    "report"
                ).strip()

                if not safe_compare(
                    password,
                    REPORT_PASSWORD
                ):
                    self.send_html(
                        page(
                            "خطا",
                            """
<div class="card center">
<h2>❌ رمز اشتباه است</h2>
<a class="btn" href="/report">
بازگشت
</a>
</div>
"""
                        ),
                        403
                    )
                    return

                if not report:
                    self.send_html(
                        page(
                            "خطا",
                            """
<div class="card center">
<h2>متن گزارش خالی است.</h2>
</div>
"""
                        ),
                        400
                    )
                    return

                if len(report) > MAX_REPORT_LENGTH:
                    self.send_html(
                        page(
                            "خطا",
                            """
<div class="card center">
<h2>گزارش بیش از حد طولانی است.</h2>
</div>
"""
                        ),
                        400
                    )
                    return

                code = create_report(report)

                self.send_html(
                    success_page(code)
                )

                return

            # =========================
            # ورود ادمین
            # =========================

            if path == "/login":

                ip = client_ip(self)

                if not login_allowed(ip):

                    self.send_html(
                        login_page(
                            "تعداد تلاش‌ها زیاد است. چند دقیقه بعد دوباره تلاش کنید."
                        ),
                        429
                    )

                    return

                password = self.get_value(
                    form,
                    "password"
                )

                register_login_attempt(ip)

                if not safe_compare(
                    password,
                    ADMIN_PASSWORD
                ):

                    self.send_html(
                        login_page(
                            "رمز عبور اشتباه است."
                        ),
                        403
                    )

                    return

          
