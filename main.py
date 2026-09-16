from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse, quote
import urllib.request
import urllib.error
import json
import html
import os
import secrets
import hmac
import time


# =========================================================
# تنظیمات
# =========================================================

PORT = int(os.environ.get("PORT", "8080"))

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")

REPORT_PASSWORD = os.environ.get("REPORT_PASSWORD", "")

SUPABASE_URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
SUPABASE_SECRET_KEY = os.environ.get("SUPABASE_SECRET_KEY", "")

SESSION_TTL = int(os.environ.get("SESSION_TTL", "3600"))

SESSIONS = {}


# =========================================================
# ابزارهای عمومی
# =========================================================

def parse_cookies(header):
    result = {}

    for part in (header or "").split(";"):
        if "=" not in part:
            continue

        name, value = part.strip().split("=", 1)
        result[name] = value

    return result


def cookie_attributes(max_age=None, http_only=True):
    parts = [
        "Path=/",
        "SameSite=Strict"
    ]

    if http_only:
        parts.append("HttpOnly")

    if os.environ.get("COOKIE_SECURE", "1") != "0":
        parts.append("Secure")

    if max_age is not None:
        parts.append("Max-Age=" + str(max_age))

    return "; ".join(parts)


# =========================================================
# نشست
# =========================================================

def create_session():
    session_token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)

    SESSIONS[session_token] = {
        "csrf_token": csrf_token,
        "expires_at": time.time() + SESSION_TTL
    }

    return session_token, csrf_token


def get_session(handler):
    cookies = parse_cookies(
        handler.headers.get("Cookie", "")
    )

    token = cookies.get("session")

    if not token:
        return None

    session = SESSIONS.get(token)

    if not session:
        return None

    if session["expires_at"] <= time.time():
        SESSIONS.pop(token, None)
        return None

    return {
        "token": token,
        **session
    }


def delete_session(token):
    if token:
        SESSIONS.pop(token, None)


def logged_in(handler):
    return get_session(handler) is not None


def csrf_valid(handler, form):
    session = get_session(handler)

    if not session:
        return False

    submitted = form.get("csrf_token", [""])[0]

    cookies = parse_cookies(
        handler.headers.get("Cookie", "")
    )

    cookie_token = cookies.get("csrf_token", "")
    expected = session["csrf_token"]

    if not submitted or not cookie_token:
        return False

    return (
        hmac.compare_digest(submitted, expected)
        and
        hmac.compare_digest(cookie_token, expected)
    )


# =========================================================
# Supabase
# =========================================================

def supabase_request(method, path, data=None, query=None):
    if not SUPABASE_URL:
        raise Exception("SUPABASE_URL تنظیم نشده است.")

    if not SUPABASE_SECRET_KEY:
        raise Exception("SUPABASE_SECRET_KEY تنظیم نشده است.")

    url = SUPABASE_URL + path

    if query:
        url += "?" + query

    headers = {
        "apikey": SUPABASE_SECRET_KEY,
        "Authorization": "Bearer " + SUPABASE_SECRET_KEY,
        "Content-Type": "application/json",
        "Prefer": "return=minimal"
    }

    body = None

    if data is not None:
        body = json.dumps(
            data,
            ensure_ascii=False
        ).encode("utf-8")

    request = urllib.request.Request(
        url,
        data=body,
        headers=headers,
        method=method
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=20
        ) as response:

            text = response.read().decode(
                "utf-8",
                errors="replace"
            )

            if not text:
                return None

            return json.loads(text)

    except urllib.error.HTTPError as error:
        body_text = error.read().decode(
            "utf-8",
            errors="replace"
        )

        print(
            "SUPABASE ERROR:",
            error.code,
            body_text
        )

        raise Exception(
            "خطای Supabase: "
            + str(error.code)
        )


# =========================================================
# قالب سایت
# =========================================================

def page(title, content):
    return f"""
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width, initial-scale=1.0">

<meta name="theme-color"
content="#050816">

<title>{html.escape(title)}</title>

<style>

* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;
    min-height: 100vh;

    font-family:
        Tahoma,
        Arial,
        sans-serif;

    color: white;

    background:
        radial-gradient(
            circle at 15% 20%,
            rgba(37,99,235,.25),
            transparent 30%
        ),
        radial-gradient(
            circle at 85% 80%,
            rgba(124,58,237,.25),
            transparent 30%
        ),
        linear-gradient(
            135deg,
            #020617,
            #071127,
            #0f172a
        );
}}

.container {{
    width: 94%;
    max-width: 1050px;
    margin: 35px auto;
}}

.card {{
    background:
        linear-gradient(
            145deg,
            rgba(30,41,59,.95),
            rgba(15,23,42,.95)
        );

    border:
        1px solid rgba(255,255,255,.08);

    border-radius: 28px;

    padding: 30px;

    margin-bottom: 22px;

    box-shadow:
        0 25px 70px rgba(0,0,0,.35);
}}

.logo {{
    width: 80px;
    height: 80px;

    margin:
        0 auto 18px;

    border-radius: 24px;

    display: flex;
    align-items: center;
    justify-content: center;

    font-size: 40px;

    background:
        linear-gradient(
            135deg,
            #2563eb,
            #7c3aed
        );
}}

h1 {{
    text-align: center;
    margin: 5px 0 12px;
    font-size: 30px;
}}

h2 {{
    margin-top: 0;
}}

.subtitle {{
    text-align: center;
    color: #94a3b8;
    line-height: 1.9;
    margin-bottom: 25px;
}}

input,
textarea,
select {{
    width: 100%;

    border:
        1px solid rgba(255,255,255,.09);

    outline: none;

    border-radius: 16px;

    padding: 15px 17px;

    font-size: 16px;

    background:
        rgba(51,65,85,.75);

    color: white;

    margin-bottom: 13px;

    font-family:
        Tahoma,
        Arial,
        sans-serif;
}}

textarea {{
    min-height: 190px;
    resize: vertical;
    line-height: 1.8;
}}

input:focus,
textarea:focus,
select:focus {{
    border-color: #3b82f6;

    box-shadow:
        0 0 0 3px
        rgba(59,130,246,.15);
}}

button {{
    width: 100%;

    border: none;

    border-radius: 16px;

    padding: 15px;

    margin-top: 6px;

    font-size: 16px;

    font-weight: bold;

    color: white;

    cursor: pointer;

    background:
        linear-gradient(
            135deg,
            #2563eb,
            #4f46e5
        );
}}

button:hover {{
    filter: brightness(1.08);
}}

.back {{
    display: block;

    text-align: center;

    color: #93c5fd;

    text-decoration: none;

    margin-top: 18px;
}}

.features {{
    display: grid;

    grid-template-columns:
        repeat(3, 1fr);

    gap: 14px;

    margin-top: 25px;
}}

.feature {{
    text-align: center;

    padding: 18px;

    border-radius: 18px;

    background:
        rgba(51,65,85,.48);
}}

.feature-icon {{
    font-size: 28px;
    margin-bottom: 8px;
}}

.feature-text {{
    color: #94a3b8;
    font-size: 13px;
    line-height: 1.7;
}}

.success {{
    padding: 25px;

    border-radius: 20px;

    text-align: center;

    background:
        linear-gradient(
            135deg,
            rgba(22,101,52,.85),
            rgba(21,128,61,.55)
        );
}}

.error {{
    padding: 20px;

    border-radius: 18px;

    text-align: center;

    background:
        linear-gradient(
            135deg,
            rgba(153,27,27,.85),
            rgba(127,29,29,.60)
        );

    word-break: break-word;
}}

.code {{
    background:
        rgba(2,6,23,.75);

    border:
        1px solid rgba(96,165,250,.15);

    border-radius: 14px;

    padding: 15px;

    text-align: center;

    font-weight: bold;

    letter-spacing: 1px;

    margin: 15px 0;

    color: #bfdbfe;
}}

.badge {{
    display: inline-block;

    padding: 7px 13px;

    border-radius: 999px;

    background:
        rgba(37,99,235,.20);

    color: #bfdbfe;

    font-size: 13px;
}}

.report {{
    background:
        rgba(30,41,59,.85);

    border:
        1px solid rgba(255,255,255,.07);

    border-radius: 20px;

    padding: 20px;

    margin-bottom: 16px;
}}

.report-text {{
    white-space: pre-wrap;

    line-height: 2;

    margin: 15px 0;
}}

.date {{
    color: #94a3b8;
    font-size: 12px;
}}

.stats {{
    display: grid;

    grid-template-columns:
        repeat(3, 1fr);

    gap: 13px;

    margin-bottom: 22px;
}}

.stat {{
    background:
        rgba(51,65,85,.60);

    border-radius: 18px;

    padding: 18px;

    text-align: center;
}}

.stat-number {{
    font-size: 30px;

    font-weight: bold;

    color: #bfdbfe;

    margin-bottom: 5px;
}}

.delete {{
    background:
        linear-gradient(
            135deg,
            #dc2626,
            #991b1b
        );
}}

.status {{
    background:
        linear-gradient(
            135deg,
            #059669,
            #047857
        );
}}

.logout {{
    background:
        linear-gradient(
            135deg,
            #475569,
            #334155
        );
}}

@media(max-width:700px) {{

    .container {{
        width: 92%;
        margin: 20px auto;
    }}

    .card {{
        padding: 20px;
        border-radius: 22px;
    }}

    h1 {{
        font-size: 25px;
    }}

    .features,
    .stats {{
        grid-template-columns: 1fr;
    }}

}}

</style>

</head>

<body>

<div class="container">

{content}

</div>

</body>
</html>
"""


# =========================================================
# صفحات
# =========================================================

def login_page(message=""):
    error = ""

    if message:
        error = f"""
<div class="error">
{html.escape(message)}
</div>
<br>
"""

    return page(
        "ورود به سامانه غدیر",
        f"""
<div class="card">

<div class="logo">
🛡️
</div>

<h1>
ورود به سامانه غدیر
</h1>

<div class="subtitle">
برای ورود، نام کاربری و رمز عبور خود را وارد کنید.
</div>

{error}

<form method="POST" action="/login">

<input
type="text"
name="username"
placeholder="👤 نام کاربری"
required
>

<input
type="password"
name="password"
placeholder="🔑 رمز عبور"
required
>

<button type="submit">
🚪 ورود
</button>

</form>

</div>
"""
    )


def home_page(csrf_token):
    return page(
        "سامانه غدیر",
        f"""
<div class="card">

<div class="logo">
🛡️
</div>

<h1>
سامانه غدیر
</h1>

<div class="subtitle">
سامانه ثبت و پیگیری گزارش‌ها
</div>

<div class="features">

<div class="feature">
<div class="feature-icon">📝</div>
<b>ثبت گزارش</b>
<div class="feature-text">
گزارش خود را ثبت کنید.
</div>
</div>

<div class="feature">
<div class="feature-icon">🔎</div>
<b>پیگیری</b>
<div class="feature-text">
با کد پیگیری وضعیت را ببینید.
</div>
</div>

<div class="feature">
<div class="feature-icon">📋</div>
<b>مدیریت</b>
<div class="feature-text">
مدیریت گزارش‌های ثبت‌شده.
</div>
</div>

</div>

<br>

<form method="GET" action="/send">
<button type="submit">
📝 ثبت گزارش جدید
</button>
</form>

<form method="GET" action="/track">
<button type="submit">
🔎 پیگیری گزارش
</button>
</form>

<form method="GET" action="/reports">
<button type="submit">
📋 پنل گزارش‌ها
</button>
</form>

<form method="POST" action="/logout">

<input
type="hidden"
name="csrf_token"
value="{html.escape(csrf_token)}"
>

<button
class="logout"
type="submit">
🚪 خروج
</button>

</form>

</div>
"""
    )


def send_page(message=""):
    extra = ""

    if message:
        extra = f"""
<div class="error">
{html.escape(message)}
</div>
<br>
"""

    return page(
        "ثبت گزارش",
        f"""
<div class="card">

<div class="logo">
📝
</div>

<h1>
ثبت گزارش
</h1>

<div class="subtitle">
گزارش خود را با دقت وارد کنید.
</div>

{extra}

<form method="POST" action="/report">

<input
type="password"
name="report_password"
placeholder="🔐 رمز ثبت گزارش"
required
>

<textarea
name="report"
placeholder="✍️ متن گزارش..."
maxlength="10000"
required
></textarea>

<button type="submit">
🚀 ثبت گزارش
</button>

</form>

<a class="back" href="/">
🏠 بازگشت
</a>

</div>
"""
    )


def success_page(code):
    return page(
        "گزارش ثبت شد",
        f"""
<div class="card">

<div class="success">

<div style="font-size:50px">
✅
</div>

<h2>
گزارش با موفقیت ثبت شد
</h2>

<p>
گزارش شما ذخیره شد.
</p>

<div class="code">

کد پیگیری

<br><br>

<span style="font-size:22px">
{html.escape(code)}
</span>

</div>

<p>
این کد را برای پیگیری نگه دارید.
</p>

</div>

<a class="back" href="/track">
🔎 پیگیری
</a>

<a class="back" href="/">
🏠 صفحه اصلی
</a>

</div>
"""
    )


def track_page(message=""):
    error = ""

    if message:
        error = f"""
<div class="error">
{html.escape(message)}
</div>
<br>
"""

    return page(
        "پیگیری گزارش",
        f"""
<div class="card">

<div class="logo">
🔎
</div>

<h1>
پیگیری گزارش
</h1>

<div class="subtitle">
کد پیگیری را وارد کنید.
</div>

{error}

<form method="GET" action="/track">

<input
type="text"
name="code"
placeholder="🎫 GHD-A1B2C3D4"
required
>

<button type="submit">
🔎 پیگیری
</button>

</form>

<a class="back" href="/">
🏠 بازگشت
</a>

</div>
"""
    )


def track_result(code):
    encoded = quote(code, safe="")

    query = (
        "select=created_at,status,tracking_code"
        "&tracking_code=eq."
        + encoded
        + "&limit=1"
    )

    reports = supabase_request(
        "GET",
        "/rest/v1/reports",
        query=query
    )

    if not reports:
        return track_page(
            "گزارشی با این کد پیدا نشد."
        )

    item = reports[0]

    status = str(
        item.get("status", "جدید")
    )

    created = str(
        item.get("created_at", "")
    )

    return page(
        "نتیجه پیگیری",
        f"""
<div class="card">

<div class="logo">
📄
</div>

<h1>
نتیجه پیگیری
</h1>

<div class="code">
🎫 کد پیگیری
<br><br>
{html.escape(code)}
</div>

<div style="text-align:center">

<div class="badge">
📌 وضعیت
</div>

<h2>
{html.escape(status)}
</h2>

</div>

<div class="code">
🕐 زمان ثبت
<br><br>
{html.escape(created)}
</div>

<a class="back" href="/track">
🔎 پیگیری دوباره
</a>

<a class="back" href="/">
🏠 صفحه اصلی
</a>

</div>
"""
    )


# =========================================================
# پنل مدیریت
# =========================================================

def reports_page(search, csrf_token):
    query = (
        "select=id,created_at,report,tracking_code,status"
        "&order=created_at.desc"
    )

    reports = supabase_request(
        "GET",
        "/rest/v1/reports",
        query=query
    )

    search = search.strip().lower()

    if search:
        reports = [
            item
            for item in reports
            if (
                search in str(
                    item.get("report", "")
                ).lower()
                or
                search in str(
                    item.get("tracking_code", "")
                ).lower()
                or
                search in str(
                    item.get("status", "")
                ).lower()
            )
        ]

    total = len(reports)

    new_count = sum(
        1
        for item in reports
        if item.get("status", "جدید") == "جدید"
    )

    checking_count = sum(
        1
        for item in reports
        if item.get("status", "") == "در حال بررسی"
    )

    checked_count = sum(
        1
        for item in reports
        if item.get("status", "") == "بررسی‌شده"
    )

    report_html = ""

    for item in reports:
        rid = str(item.get("id", ""))

        report_text = str(
            item.get("report", "")
        )

        created = str(
            item.get("created_at", "")
        )

        tracking = str(
            item.get("tracking_code", "")
        )

        status = str(
            item.get("status", "جدید")
        )

        report_html += f"""
<div class="report">

<div class="badge">
📌 {html.escape(status)}
</div>

<div class="code">
🎫 {html.escape(tracking)}
</div>

<div class="report-text">
{html.escape(report_text)}
</div>

<div class="date">
🕐 {html.escape(created)}
</div>

<br>

<form method="POST" action="/status">

<input
type="hidden"
name="id"
value="{html.escape(rid)}"
>

<input
type="hidden"
name="csrf_token"
value="{html.escape(csrf_token)}"
>

<select name="status">

<option value="جدید">
جدید
</option>

<option value="در حال بررسی">
در حال بررسی
</option>

<option value="بررسی‌شده">
بررسی‌شده
</option>

</select>

<button class="status" type="submit">
💾 تغییر وضعیت
</button>

</form>

<form method="POST" action="/delete">

<input
type="hidden"
name="id"
value="{html.escape(rid)}"
>

<input
type="hidden"
name="csrf_token"
value="{html.escape(csrf_token)}"
>

<button
class="delete"
type="submit">
🗑️ حذف گزارش
</button>

</form>

</div>
"""

    if not report_html:
        report_html = """
<div class="card" style="text-align:center">

<div style="font-size:45px">
📭
</div>

<h3>
گزارشی پیدا نشد
</h3>

</div>
"""

    return page(
        "پنل مدیریت",
        f"""
<div class="card">

<div class="logo">
📋
</div>

<h1>
پنل مدیریت
</h1>

<div class="stats">

<div class="stat">
<div class="stat-number">
{total}
</div>
کل گزارش‌ها
</div>

<div class="stat">
<div class="stat-number">
{new_count}
</div>
گزارش جدید
</div>

<div class="stat">
<div class="stat-number">
{checked_count}
</div>
بررسی‌شده
</div>

</div>

<div class="stat">
<div class="stat-number">
{checking_count}
</div>
در حال بررسی
</div>

<br>

<form method="GET" action="/reports">

<input
type="text"
name="search"
value="{html.escape(search)}"
placeholder="🔎 جست‌وجو..."
>

<button type="submit">
🔍 جست‌وجو
</button>

</form>

<br>

{report_html}

<form method="POST" action="/logout">

<input
type="hidden"
name="csrf_token"
value="{html.escape(csrf_token)}"
>

<button class="logout" type="submit">
🚪 خروج
</button>

</form>

<a class="back" href="/">
🏠 صفحه اصلی
</a>

</div>
"""
    )


# =========================================================
# پاسخ‌های HTTP
# =========================================================

class Server(BaseHTTPRequestHandler):

    server_version = "GhadeerServer/1.0"

    def send_html(self, content, status=200):
        data = content.encode("utf-8")

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
            "Cache-Control",
            "no-store"
        )

        self.end_headers()

        self.wfile.write(data)

    def redirect(self, location):
        self.send_response(302)

        self.send_header(
            "Location",
            location
        )

        self.end_headers()

    # =====================================================
    # GET
    # =====================================================

    def do_GET(self):
        parsed = urlparse(self.path)

        path = parsed.path

        params = parse_qs(
            parsed.query
        )

        try:

            if path == "/":
 
