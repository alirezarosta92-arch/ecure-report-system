import os
import json
import time
import secrets
import hmac
import urllib.request
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs


# =========================
# تنظیمات
# =========================

PORT = int(os.environ.get("PORT", "10000"))

SUPABASE_URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
SUPABASE_KEY = os.environ.get("SUPABASE_SECRET_KEY", "")

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")

REPORT_PASSWORD = os.environ.get("REPORT_PASSWORD", "")

SESSION_TTL = 2 * 60 * 60
MAX_REPORT_LENGTH = 10000

sessions = {}


# =========================
# ابزارهای امنیتی
# =========================

def new_token():
    return secrets.token_urlsafe(32)


def create_session():
    token = new_token()
    csrf = new_token()

    sessions[token] = {
        "csrf": csrf,
        "expires": time.time() + SESSION_TTL
    }

    return token, csrf


def get_session(handler):
    cookie = handler.headers.get("Cookie", "")

    for item in cookie.split(";"):
        item = item.strip()

        if item.startswith("session="):
            token = item.split("=", 1)[1]

            session = sessions.get(token)

            if not session:
                return None

            if session["expires"] < time.time():
                sessions.pop(token, None)
                return None

            return {
                "token": token,
                **session
            }

    return None


def logged_in(handler):
    return get_session(handler) is not None


def cookie(name, value, max_age=None, http_only=True):
    result = f"{name}={value}; Path=/; SameSite=Strict; Secure"

    if http_only:
        result += "; HttpOnly"

    if max_age is not None:
        result += f"; Max-Age={max_age}"

    return result


def csrf_valid(handler, data):
    session = get_session(handler)

    if not session:
        return False

    submitted = data.get("csrf", [""])[0]

    if not submitted:
        return False

    return hmac.compare_digest(
        submitted,
        session["csrf"]
    )


def escape(text):
    text = str(text)

    replacements = {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#x27;"
    }

    for a, b in replacements.items():
        text = text.replace(a, b)

    return text


# =========================
# Supabase
# =========================

def supabase_request(method, path, data=None):

    if not SUPABASE_URL or not SUPABASE_KEY:
        raise Exception("تنظیمات Supabase در Render کامل نیست.")

    url = SUPABASE_URL + path

    headers = {
        "apikey": SUPABASE_KEY,
        "Authorization": "Bearer " + SUPABASE_KEY,
        "Content-Type": "application/json",
        "Prefer": "return=minimal"
    }

    body = None

    if data is not None:
        body = json.dumps(data).encode("utf-8")

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

            result = response.read().decode("utf-8")

            if not result:
                return None

            return json.loads(result)

    except Exception as e:
        print("SUPABASE ERROR:", repr(e))
        raise


# =========================
# HTML
# =========================

def page(title, content):

    return f"""
<!DOCTYPE html>

<html lang="fa" dir="rtl">

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width, initial-scale=1.0">

<meta name="theme-color" content="#050816">

<title>{escape(title)}</title>

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
            circle at 10% 10%,
            rgba(37,99,235,.25),
            transparent 30%
        ),
        radial-gradient(
            circle at 90% 90%,
            rgba(124,58,237,.25),
            transparent 30%
        ),
        linear-gradient(
            135deg,
            #020617,
            #071127,
            #0f172a
        );

    padding: 25px 0;
}}

.container {{
    width: 94%;
    max-width: 900px;
    margin: auto;
}}

.card {{
    background:
        linear-gradient(
            145deg,
            rgba(30,41,59,.94),
            rgba(15,23,42,.96)
        );

    border:
        1px solid rgba(255,255,255,.08);

    border-radius: 25px;

    padding: 28px;

    margin-bottom: 20px;

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

    box-shadow:
        0 15px 35px
        rgba(37,99,235,.30);
}}

h1 {{
    text-align: center;
    font-size: 29px;
    margin: 8px 0;
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
        1px solid
        rgba(255,255,255,.09);

    outline: none;

    border-radius: 15px;

    padding: 15px;

    margin-bottom: 13px;

    background:
        rgba(51,65,85,.75);

    color: white;

    font-size: 16px;

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

    border: 0;

    border-radius: 15px;

    padding: 15px;

    margin-top: 6px;

    color: white;

    font-size: 16px;

    font-weight: bold;

    cursor: pointer;

    background:
        linear-gradient(
            135deg,
            #2563eb,
            #4f46e5
        );

    transition: .2s;
}}

button:hover {{
    transform: translateY(-2px);
}}

.red {{
    background:
        linear-gradient(
            135deg,
            #dc2626,
            #991b1b
        );
}}

.green {{
    background:
        linear-gradient(
            135deg,
            #059669,
            #047857
        );
}}

.gray {{
    background:
        linear-gradient(
            135deg,
            #475569,
            #334155
        );
}}

.menu {{
    display: grid;

    grid-template-columns:
        repeat(2, 1fr);

    gap: 15px;

    margin-top: 25px;
}}

.menu a {{
    text-decoration: none;

    color: white;

    padding: 25px 15px;

    border-radius: 18px;

    text-align: center;

    background:
        rgba(51,65,85,.65);

    border:
        1px solid
        rgba(255,255,255,.07);

    transition: .2s;
}}

.menu a:hover {{
    transform: translateY(-3px);
    border-color: #3b82f6;
}}

.menu-icon {{
    font-size: 32px;
    margin-bottom: 8px;
}}

.back {{
    display: block;

    text-align: center;

    color: #93c5fd;

    text-decoration: none;

    margin-top: 18px;
}}

.success {{
    padding: 25px;

    border-radius: 18px;

    text-align: center;

    background:
        rgba(22,101,52,.7);
}}

.error {{
    padding: 20px;

    border-radius: 18px;

    text-align: center;

    background:
        rgba(153,27,27,.75);

    margin-bottom: 20px;
}}

.code {{
    padding: 15px;

    margin: 15px 0;

    border-radius: 14px;

    text-align: center;

    background:
        rgba(2,6,23,.75);

    color: #bfdbfe;

    font-size: 20px;

    font-weight: bold;

    letter-spacing: 1px;
}}

.report {{
    padding: 20px;

    margin-bottom: 15px;

    border-radius: 19px;

    background:
        rgba(51,65,85,.65);

    border:
        1px solid
        rgba(255,255,255,.07);
}}

.badge {{
    display: inline-block;

    padding: 7px 12px;

    border-radius: 999px;

    background:
        rgba(37,99,235,.2);

    color: #bfdbfe;

    font-size: 13px;
}}

.report-text {{
    white-space: pre-wrap;

    line-height: 2;

    margin: 16px 0;
}}

.date {{
    color: #94a3b8;
    font-size: 12px;
}}

.stats {{
    display: grid;

    grid-template-columns:
        repeat(3, 1fr);

    gap: 12px;

    margin-bottom: 20px;
}}

.stat {{
    padding: 18px;

    border-radius: 17px;

    text-align: center;

    background:
        rgba(51,65,85,.55);
}}

.stat-number {{
    font-size: 28px;
    font-weight: bold;
    color: #bfdbfe;
}}

@media(max-width:650px) {{

    .card {{
        padding: 20px;
        border-radius: 21px;
    }}

    .menu {{
        grid-template-columns: 1fr;
    }}

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


# =========================
# صفحات
# =========================

def login_page(message=""):

    error = ""

    if message:
        error = f"""
<div class="error">
{escape(message)}
</div>
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
autocomplete="username"
required
>

<input
type="password"
name="password"
placeholder="🔐 رمز عبور"
autocomplete="current-password"
required
>

<button type="submit">
🚪 ورود
</button>

</form>

</div>

"""
    )


def home_page(csrf):

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
پنل اصلی سامانه ثبت و پیگیری گزارش‌ها
</div>

<div class="menu">

<a href="/send">
<div class="menu-icon">📝</div>
ثبت گزارش
</a>

<a href="/track">
<div class="menu-icon">🔎</div>
پیگیری گزارش
</a>

<a href="/reports">
<div class="menu-icon">📋</div>
مدیریت گزارش‌ها
</a>

</div>

<form method="POST" action="/logout">

<input
type="hidden"
name="csrf"
value="{escape(csrf)}"
>

<button
class="gray"
type="submit"
>
🚪 خروج
</button>

</form>

</div>

"""
    )


def send_page(message=""):

    error = ""

    if message:
        error = f"""
<div class="error">
{escape(message)}
</div>
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
متن گزارش را وارد کنید.
</div>

{error}

<form method="POST" action="/submit">

<input
type="password"
name="report_password"
placeholder="🔐 رمز ثبت گزارش"
required
>

<textarea
name="report"
maxlength="{MAX_REPORT_LENGTH}"
placeholder="✍️ متن گزارش..."
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

{escape(code)}

</div>

<p>
کد پیگیری را برای خودتان نگه دارید.
</p>

</div>

<a class="back" href="/track">
🔎 پیگیری گزارش
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
{escape(message)}
</div>
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
placeholder="🎫 مثال: GHD-A1B2C3D4"
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

    encoded = urllib.parse.quote(
        code,
        safe=""
    )

    path = (
        "/rest/v1/reports"
        "?select=created_at,status,tracking_code"
        "&tracking_code=eq."
        + encoded
    )

    reports = supabase_request(
        "GET",
        path
    )

    if not reports:

        return track_page(
            "گزارشی با این کد پیدا نشد."
        )

    item = reports[0]

    status = item.get(
        "status",
        "جدید"
    )

    created = item.get(
        "created_at",
        ""
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

🎫 {escape(code)}

</div>

<div style="text-align:center">

<div class="badge">
وضعیت گزارش
</div>

<h2>
{escape(status)}
</h2>

<p class="date">
🕐 زمان ثبت:
<br>
{escape(created)}
</p>

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


def reports_page(search="", csrf=""):

    path = (
        "/rest/v1/reports"
        "?select=id,created_at,report,tracking_code,status"
        "&order=created_at.desc"
    )

    reports = supabase_request(
        "GET",
        path
    )

    search = search.strip().lower()

    if search:

        reports = [
            x for x in reports
            if (
                search in str(
                    x.get("report", "")
                ).lower()
                or
                search in str(
                    x.get("tracking_code", "")
                ).lower()
                or
                search in str(
                    x.get("status", "")
                ).lower()
            )
        ]

    total = len(reports)

    new_count = sum(
        1 for x in reports
        if x.get("status", "جدید") == "جدید"
    )

    checking_count = sum(
        1 for x in reports
        if x.get("status", "") == "در حال بررسی"
    )

    checked_count = sum(
        1 for x in reports
        if x.get("status", "") == "بررسی‌شده"
    )

    html_reports = ""

    for item in reports:

        rid = str(
            item.get("id", "")
        )

        text = str(
            item.get("report", "")
        )

        created = str(
            item.get("created_at", "")
        )

        code = str(
            item.get("tracking_code", "")
        )

        status = str(
            item.get("status", "جدید")
        )

        html_reports += f"""

<div class="report">

<div class="badge">
📌 {escape(status)}
</div>

<div class="code">
🎫 {escape(code)}
</div>

<div class="report-text">
{escape(text)}
</div>

<div class="date">
🕐 {escape(created)}
</div>

<form method="POST" action="/status">

<input
type="hidden"
name="csrf"
value="{escape(csrf)}"
>

<input
type="hidden"
name="id"
value="{escape(rid)}"
>

<select name="status">

<option
value="جدید"
{"selected" if status == "جدید" else ""}
>
جدید
</option>

<option
value="در حال بررسی"
{"selected" if status == "در حال بررسی" else ""}
>
در حال بررسی
</option>

<option
value="بررسی‌شده"
{"selected" if status == "بررسی‌شده" else ""}
>
بررسی‌شده
</option>

</select>

<button
class="green"
type="submit"
>
💾 تغییر وضعیت
</button>

</form>

<form method="POST" action="/delete">

<input
type="hidden"
name="csrf"
value="{escape(csrf)}"
>

<input
type="hidden"
name="id"
value="{escape(rid)}"
>

<button
class="red"
type="submit"
>
🗑️ حذف گزارش
</button>

</form>

</div>

"""

    if not html_reports:

        html_reports = """
<div class="report" style="text-align:center">
📭
<br><br>
گزارشی پیدا نشد.
</div>
"""

    return page(
        "مدیریت گزارش‌ها",
        f"""

<div class="card">

<div class="logo">
📋
</div>

<h1>
مدیریت گزارش‌ها
</h1>

<div class="stats">

<div class="stat">
<div class="stat-number">
{total}
</div>
کل
</div>

<div class="stat">
<div class="stat-number">
{new_count}
</div>
جدید
</div>

<div class="stat">
<div class="stat-number">
{checked_count}
</div>
بررسی‌شده
</div>

</div>

<div class="stat" style="margin-bottom:20px">

<div class="stat-number">
{checking_count}
</div>

در حال بررسی

</div>

<form method="GET" action="/reports">

<input
type="text"
name="search"
value="{escape(search)}"
placeholder="🔎 جست‌وجو..."
>

<button type="submit">
🔍 جست‌وجو
</button>

</form>

{html_reports}

<a class="back" href="/">
🏠 صفحه اصلی
</a>

</div>

"""
    )


# =========================
# Handler
# =========================

class Handler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        return

    def send_html(self, content, status=200):

        body = content.encode("utf-8")

        self.send_response(status)

        self.send_header(
            "Content-Type",
            "text/html; charset=utf-8"
        )

        self.send_header(
            "Content-Length",
            str(len(body))
        )

        self.send_header(
            "Cache-Control",
            "no-store"
        )

        self.end_headers()

        self.wfile.write(body)

    def redirect(self, location):

        self.send_response(302)

        self.send_header(
            "Location",
            location
        )

        self.end_headers()

    def read_post(self):

        length = int(
            self.headers.get(
                "Content-Length",
                "0"
            )
        )

        if length > 1024 * 1024:
            raise Exception(
                "درخواست بیش از حد مجاز است."
            )

        body = self.rfile.read(
            length
        ).decode(
            "utf-8",
            errors="replace"
        )

        return parse_qs(body)

    # =====================
    # GET
    # =====================

    def do_GET(self):

        parsed = urlparse(
            self.path
        )

        path = parsed.path

        params = parse_qs(
            parsed.query
        )

        try:

            # صفحه اصلی

            if path == "/":

                session = get_session(self)

                if not session:
                    self.redirect("/login")
                    return

                self.send_html(
                    home_page(
                        session["csrf"]
                    )
                )

                return

            # ورود

            if path == "/login":

                if logged_in(self):
                    self.redirect("/")
                    return

                self.send_html(
                    login_page()
                )

                return

            # ثبت گزارش

            if path == "/send":

                if not logged_in(self):
                    self.redirect("/login")
                    return

                self.send_html(
                    send_page()
                )

                return

            # پیگیری

            if path == "/track":

                if not logged_in(self):
                    self.redirect("/login")
                    return

                code = params.get(
                    "code",
                    [""]
                )[0].strip()

                if code:

                    self.send_html(
                        track_result(code)
                    )

                else:

                    self.send_html(
                        track_page()
                    )

                return

            # گزارش‌ها

            if path == "/reports":

                session = get_session(self)

                if not session:
                    self.redirect("/login")
                    return

                search = params.get(
                    "search",
                    [""]
                )[0]

                self.send_html(
                    reports_page(
                        search,
           
