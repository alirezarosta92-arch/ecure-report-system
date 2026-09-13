import os
import json
import html
import secrets
import hashlib
import hmac
import re
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

# =========================
# SETTINGS
# =========================

HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "10000"))

SUPABASE_URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
SUPABASE_KEY = os.environ.get("SUPABASE_SECRET_KEY", "")

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
REPORT_PASSWORD = os.environ.get("REPORT_PASSWORD", "")

SESSION_TTL = 2 * 60 * 60
MAX_REPORT_LENGTH = 10000

SESSIONS = {}
LOGIN_ATTEMPTS = {}

# =========================
# SECURITY HELPERS
# =========================

def now():
    return time.time()


def clean_sessions():
    current = now()

    expired = [
        token
        for token, data in SESSIONS.items()
        if data["expires"] < current
    ]

    for token in expired:
        SESSIONS.pop(token, None)


def create_session():
    clean_sessions()

    token = secrets.token_urlsafe(48)
    csrf = secrets.token_urlsafe(32)

    SESSIONS[token] = {
        "expires": now() + SESSION_TTL,
        "csrf": csrf
    }

    return token, csrf


def get_session(handler):
    clean_sessions()

    cookie = handler.headers.get("Cookie", "")

    for item in cookie.split(";"):
        item = item.strip()

        if item.startswith("session="):
            token = item.split("=", 1)[1]

            session = SESSIONS.get(token)

            if session and session["expires"] > now():
                return token, session

    return None, None


def is_logged_in(handler):
    token, session = get_session(handler)
    return token is not None and session is not None


def check_login_limit(ip):
    current = now()

    data = LOGIN_ATTEMPTS.get(ip)

    if not data:
        return True

    if current > data["reset"]:
        LOGIN_ATTEMPTS.pop(ip, None)
        return True

    return data["count"] < 5


def failed_login(ip):
    current = now()

    data = LOGIN_ATTEMPTS.get(ip)

    if not data or current > data["reset"]:
        LOGIN_ATTEMPTS[ip] = {
            "count": 1,
            "reset": current + 600
        }
    else:
        data["count"] += 1


def password_ok(given, real):
    if not given or not real:
        return False

    return hmac.compare_digest(given, real)


def safe_text(value):
    return html.escape(str(value or ""))


def tracking_code():
    return "GHD-" + secrets.token_hex(5).upper()


def valid_tracking(code):
    return bool(re.fullmatch(r"GHD-[A-F0-9]{10}", code or ""))


# =========================
# SUPABASE
# =========================

def supabase_request(method, path, payload=None, params=""):
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise RuntimeError("Supabase is not configured")

    url = SUPABASE_URL + path

    if params:
        url += "?" + params

    headers = {
        "apikey": SUPABASE_KEY,
        "Authorization": "Bearer " + SUPABASE_KEY,
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    body = None

    if payload is not None:
        body = json.dumps(payload).encode("utf-8")

    request = Request(
        url,
        data=body,
        headers=headers,
        method=method
    )

    try:
        with urlopen(request, timeout=15) as response:
            raw = response.read()

            if not raw:
                return []

            return json.loads(raw.decode("utf-8"))

    except HTTPError as e:
        raise RuntimeError("Database request failed")

    except URLError:
        raise RuntimeError("Database connection failed")


def create_report(text):
    code = tracking_code()

    data = {
        "report": text,
        "tracking_code": code,
        "status": "جدید"
    }

    result = supabase_request(
        "POST",
        "/rest/v1/reports",
        data,
        "select=id,created_at,tracking_code,status"
    )

    if not result:
        return code

    return result[0].get("tracking_code", code)


def get_reports():
    return supabase_request(
        "GET",
        "/rest/v1/reports",
        params="select=id,created_at,report,tracking_code,status&order=id.desc"
    )


def get_report_by_code(code):
    result = supabase_request(
        "GET",
        "/rest/v1/reports",
        params=(
            "select=id,created_at,tracking_code,status"
            "&tracking_code=eq." + code
        )
    )

    return result[0] if result else None


def update_status(report_id, status):
    allowed = {
        "جدید",
        "در حال بررسی",
        "بررسی شد",
        "بسته شد"
    }

    if status not in allowed:
        return False

    supabase_request(
        "PATCH",
        "/rest/v1/reports",
        {"status": status},
        "id=eq." + str(int(report_id))
    )

    return True


def delete_report(report_id):
    supabase_request(
        "DELETE",
        "/rest/v1/reports",
        params="id=eq." + str(int(report_id))
    )


# =========================
# HTML
# =========================

CSS = """
* {
    box-sizing: border-box;
}

body {
    margin: 0;
    font-family: Tahoma, Arial, sans-serif;
    background:
        radial-gradient(circle at top left, #172554, transparent 35%),
        radial-gradient(circle at bottom right, #312e81, transparent 35%),
        #050816;
    color: #fff;
    min-height: 100vh;
}

.container {
    width: min(1050px, 92%);
    margin: auto;
}

nav {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 22px 0;
}

.logo {
    font-size: 24px;
    font-weight: bold;
}

.logo span {
    color: #60a5fa;
}

.card {
    background: rgba(15, 23, 42, .78);
    border: 1px solid rgba(96, 165, 250, .22);
    border-radius: 24px;
    padding: 28px;
    margin: 25px 0;
    box-shadow: 0 20px 70px rgba(0,0,0,.35);
    backdrop-filter: blur(15px);
}

.hero {
    text-align: center;
    padding: 65px 20px 35px;
}

.shield {
    width: 95px;
    height: 95px;
    margin: auto;
    border-radius: 30px;
    display: flex;
    align-items: center;
    justify-content: center;
    background: linear-gradient(135deg, #2563eb, #7c3aed);
    font-size: 45px;
    box-shadow: 0 0 50px rgba(59,130,246,.45);
}

h1 {
    font-size: 42px;
    margin: 25px 0 10px;
}

h2 {
    margin-top: 0;
}

.subtitle {
    color: #a5b4fc;
    line-height: 1.9;
}

textarea,
input,
select {
    width: 100%;
    padding: 15px;
    margin: 8px 0 15px;
    border-radius: 14px;
    border: 1px solid #334155;
    background: #020617;
    color: white;
    font-size: 16px;
    outline: none;
}

textarea {
    min-height: 180px;
    resize: vertical;
}

button,
.btn {
    display: inline-block;
    border: 0;
    border-radius: 14px;
    padding: 14px 22px;
    background: linear-gradient(135deg, #2563eb, #7c3aed);
    color: white;
    font-weight: bold;
    cursor: pointer;
    text-decoration: none;
}

button:hover,
.btn:hover {
    opacity: .9;
}

.grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 18px;
}

.report {
    background: rgba(2, 6, 23, .7);
    border: 1px solid #1e293b;
    padding: 20px;
    border-radius: 18px;
    margin: 15px 0;
}

.code {
    font-size: 23px;
    color: #60a5fa;
    font-weight: bold;
    letter-spacing: 2px;
}

.status {
    display: inline-block;
    padding: 7px 12px;
    border-radius: 20px;
    background: #172554;
    color: #93c5fd;
}

.danger {
    background: #991b1b;
}

.muted {
    color: #94a3b8;
}

.center {
    text-align: center;
}

.error {
    color: #fca5a5;
    background: rgba(127,29,29,.3);
    padding: 12px;
    border-radius: 12px;
    margin-bottom: 15px;
}

.success {
    color: #86efac;
    background: rgba(20,83,45,.3);
    padding: 15px;
    border-radius: 12px;
}

@media(max-width:700px) {
    h1 {
        font-size: 31px;
    }

    .grid {
        grid-template-columns: 1fr;
    }

    .card {
        padding: 20px;
    }

    nav {
        gap: 10px;
    }
}
"""


def page(title, content):
    return f"""<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{safe_text(title)}</title>
<style>{CSS}</style>
</head>
<body>
<div class="container">
<nav>
<div class="logo">🛡️ <span>سامانه غدیر</span></div>
<a class="btn" href="/">خانه</a>
</nav>
{content}
</div>
</body>
</html>
"""


# =========================
# HANDLER
# =========================

class Handler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        return

    def send_page(self, content, status=200, cookies=None):
        data = content.encode("utf-8")

        self.send_response(status)

        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))

        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=()"
        )
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'unsafe-inline'; form-action 'self'"
        )

        if cookies:
            for cookie in cookies:
                self.send_header("Set-Cookie", cookie)

        self.end_headers()
        self.wfile.write(data)

    def redirect(self, location, cookies=None):
        self.send_response(303)
        self.send_header("Location", location)

        if cookies:
            for cookie in cookies:
                self.send_header("Set-Cookie", cookie)

        self.end_headers()

    def read_body(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return b""

        if length > 15000:
            return None

        return self.rfile.read(length)

    def form_data(self):
        body = self.read_body()

        if body is None:
            return None

        try:
            text = body.decode("utf-8")
            parsed = parse_qs(text, keep_blank_values=True)

            return {
                key: values[0]
                for key, values in parsed.items()
            }

        except Exception:
            return None

    def require_csrf(self, form):
        _, session = get_session(self)

        if not session:
            return False

        token = form.get("csrf", "")

        return hmac.compare_digest(
            token,
            session["csrf"]
        )

    def do_GET(self):
        path = urlparse(self.path).path

        try:
            if path == "/":
                self.home()
                return

            if path == "/report":
                self.report_page()
                return

            if path == "/track":
                self.track_page()
                return

            if path == "/admin":
                self.admin_login()
                return

            if path == "/reports":
                if not is_logged_in(self):
                    self.redirect("/admin")
                    return

                self.dashboard()
                return

            if path == "/logout":
                token, _ = get_session(self)

                if token:
                    SESSIONS.pop(token, None)

                self.redirect(
                    "/admin",
                    cookies=[
                        "session=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Strict"
                    ]
                )
                return

            self.send_page(
                page(
                    "404",
                    '<div class="card center"><h2>صفحه پیدا نشد</h2></div>'
                ),
                404
            )

        except Exception:
            self.send_page(
                page(
                    "خطا",
                    '<div class="card center"><h2>خطایی رخ داد</h2></div>'
                ),
                500
            )

    def do_POST(self):
        path = urlparse(self.path).path

        try:
            if path == "/submit":
                self.submit_report()
                return

            if path == "/login":
                self.login()
                return

            if path == "/status":
                self.change_status()
                return

            if path == "/delete":
                self.remove_report()
                return

            self.send_page(
                page(
                    "404",
                    '<div class="card center"><h2>درخواست نامعتبر</h2></div>'
                ),
                404
            )

        except Exception:
            self.send_page(
                page(
                    "خطا",
                    '<div class="card center"><h2>خطایی رخ داد</h2></div>'
                ),
                500
            )

    # =========================
    # PAGES
    # =========================

    def home(self):
        content = """
<div class="hero">
<div class="shield">🛡️</div>
<h1>سامانه غدیر</h1>
<p class="subtitle">
سامانه ثبت و پیگیری گزارش‌ها
<br>
ساده، آنلاین و قابل استفاده در دستگاه‌های مختلف
</p>

<div class="grid">
<div class="card">
<h2>📝 ثبت گزارش</h2>
<p class="muted">
گزارش خود را ثبت کنید و کد پیگیری دریافت کنید.
</p>
<a class="btn" href="/report">ثبت گزارش</a>
</div>

<div class="card">
<h2>🔎 پیگیری</h2>
<p class="muted">
با کد پیگیری، وضعیت گزارش را مشاهده کنید.
</p>
<a class="btn" href="/track">پیگیری گزارش</a>
</div>
</div>

<div class="card center">
<h2>🔐 مدیریت</h2>
<a class="btn" href="/admin">ورود مدیریت</a>
</div>
</div>
"""

        self.send_page(page("سامانه غدیر", content))

    def report_page(self, error=""):
        error_html = ""

        if error:
            error_html = f'<div class="error">{safe_text(error)}</div>'

        content = f"""
<div class="card">
<h1>📝 ثبت گزارش</h1>

{error_html}

<form method="post" action="/submit">

<label>رمز ثبت گزارش</label>
<input
type="password"
name="password"
maxlength="100"
required
>

<label>متن گزارش</label>
<textarea
name="report"
maxlength="{MAX_REPORT_LENGTH}"
required
placeholder="گزارش خود را اینجا بنویسید..."
></textarea>

<button type="submit">🔒 ثبت امن گزارش</button>

</form>
</div>
"""

        self.send_page(page("ثبت گزارش", content))

    def track_page(self, message=""):
        message_html = ""

        if message:
            message_html = message

        content = f"""
<div class="card">
<h1>🔎 پیگیری گزارش</h1>

{message_html}

<form method="get" action="/track">

<label>کد پیگیری</label>
<input
name="code"
placeholder="GHD-XXXXXXXXXX"
maxlength="14"
required
>

<button type="submit">پیگیری</button>

</form>
</div>
"""

        query = parse_qs(urlparse(self.path).query)
        code = query.get("code", [""])[0].strip().upper()

        if code:
            if not valid_tracking(code):
                content += """
<div class="card">
<div class="error">
کد پیگیری نامعتبر است.
</div>
</div>
"""
            else:
                report = get_report_by_code(code)

                if not report:
                    content += """
<div class="card">
<div class="error">
گزارشی با این کد پیدا نشد.
</div>
</div>
"""
                else:
                    content += f"""
<div class="card center">
<h2>گزارش پیدا شد ✅</h2>
<p>کد پیگیری</p>
<div class="code">{safe_text(report.get("tracking_code"))}</div>
<br>
<p>وضعیت</p>
<div class="status">{safe_text(report.get("status"))}</div>
<br><br>
<p class="muted">
زمان ثبت: {safe_text(report.get("created_at"))}
</p>
</div>
"""

        self.send_page(page("پیگیری گزارش", content))

    def admin_login(self, error=""):
        error_html = ""

        if error:
            error_html = f'<div class="error">{safe_text(error)}</div>'

        content = f"""
<div class="card center">
<h1>🔐 مدیریت</h1>

{error_html}

<form method="post" action="/login">

<input
type="password"
name="password"
maxlength="100"
placeholder="رمز مدیریت"
required
>

<button type="submit">ورود</button>

</form>
</div>
"""

        self.send_page(page("ورود مدیریت", content))

    # =========================
    # ACTIONS
    # =========================

    def submit_report(self):
        form = self.form_data()

        if not form:
            self.report_page("درخواست نامعتبر است.")
            return

        password = form.get("password", "")
        report = form.get("report", "").strip()

        if not password_ok(password, REPORT_PASSWORD):
            self.report_page("رمز ثبت گزارش اشتباه است.")
            return

        if not report:
            self.report_page("متن گزارش خالی است.")
            return

        if len(report) > MAX_REPORT_LENGTH:
            self.report_page("گزارش بیش از حد طولانی است.")
            return

        code = create_report(report)

        content = f"""
<div class="card center">
<h1>✅ گزارش ثبت شد</h1>

<p>گزارش شما با موفقیت ثبت شد.</p>

<p>کد پیگیری خود را نگه دارید:</p>

<div class="code">{safe_text(code)}</div>

<br>

<a class="btn" href="/track?code={safe_text(code)}">
پیگیری گزارش
</a>

</div>
"""

        self.send_page(page("گزارش ثبت شد", content))

    def login(self):
        form = self.form_data()

        if not form:
            self.admin_login("درخواست نامعتبر است.")
            return

        ip = self.client_address[0]

        if not check_login_limit(ip):
            self.admin_login(
                "تعداد تلاش‌های ورود زیاد است. کمی بعد دوباره تلاش کنید."
            )
            return

        password = form.get("password", "")

        if not password_ok(password, ADMIN_PASSWORD):
            failed_login(ip)
            self.admin_login("رمز مدیریت اشتباه است.")
            return

        LOGIN_ATTEMPTS.pop(ip, None)

        token, csrf = create_session()

        cookies = [
            "session=" + token +
            "; Path=/; HttpOnly; Secure; SameSite=Strict"
        ]

        self.redirect("/reports", cookies)

    def dashboard(self):
        reports = get_reports()

        _, session = get_session(self)

        csrf = session["csrf"]

        total = len(reports)

        new_count = sum(
            1 for r in reports
            if r.get("status") == "جدید"
        )

        checking_count = sum(
            1 for r in reports
            if r.get("status") == "در حال بررسی"
        )

        closed_count = sum(
            1 for r in reports
            if r.get("status") == "بسته شد"
        )

        content = f"""
<div class="card">
<div style="display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap">
<div>
<h1>📊 داشبورد مدیریت</h1>
<p class="muted">مدیریت گزارش‌های ثبت‌شده</p>
</div>
<a class="btn" href="/logout">خروج</a>
</div>
</div>

<div class="grid">

<div class="card center">
<h2>{total}</h2>
<p class="muted">کل گزارش‌ها</p>
</div>

<div class="card center">
<h2>{new_count}</h2>
<p class="muted">گزارش جدید</p>
</div>

<div class="card center">
<h2>{checking_count}</h2>
<p class="muted">در حال بررسی</p>
</div>

<div class="card center">
<h2>{closed_count}</h2>
<p class="muted">بسته شده</p>
</div>

</div>
"""

        if not reports:
            content += """
<div class="card center">
<h2>هنوز گزارشی ثبت نشده است.</h2>
</div>
"""

        for report in reports:
            rid = report.get("id")
            code = report.get("tracking_code", "")
            status = report.get("status", "جدید")
            text = report.get("report", "")
            created = report.get("created_at", "")

            content += f"""
<div class="report">

<div class="code">
{safe_text(code)}
</div>

<p>{safe_text(text)}</p>

<p class="muted">
{safe_text(created)}
</p>

<div class="grid">

<form method="post" action="/status">
<input type="hid
