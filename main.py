import os
import json
import time
import secrets
import hmac
import urllib.request
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

# =========================
# تنظیمات
# =========================

PORT = int(os.getenv("PORT", "10000"))

SUPABASE_URL = os.getenv(
    "SUPABASE_URL",
    ""
).rstrip("/")

SUPABASE_KEY = os.getenv(
    "SUPABASE_SECRET_KEY",
    ""
)

ADMIN_PASSWORD = os.getenv(
    "ADMIN_PASSWORD",
    ""
)

REPORT_PASSWORD = os.getenv(
    "REPORT_PASSWORD",
    ""
)

sessions = {}

login_attempts = {}

SESSION_TIME = 2 * 60 * 60

MAX_REPORT_LENGTH = 10000


# =========================
# Supabase
# =========================

def supabase_request(method, url, data=None):

    headers = {
        "apikey": SUPABASE_KEY,
        "Authorization": "Bearer " + SUPABASE_KEY,
        "Content-Type": "application/json",
        "Prefer": "return=representation"
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

    with urllib.request.urlopen(
        request,
        timeout=20
    ) as response:

        result = response.read().decode(
            "utf-8"
        )

        if not result:
            return None

        return json.loads(result)


# =========================
# Session
# =========================

def cookies(handler):

    result = {}

    raw = handler.headers.get(
        "Cookie",
        ""
    )

    for item in raw.split(";"):

        if "=" in item:

            key, value = item.strip().split(
                "=",
                1
            )

            result[key] = value

    return result


def get_session(handler):

    token = cookies(
        handler
    ).get(
        "session"
    )

    if not token:
        return None

    session = sessions.get(
        token
    )

    if not session:
        return None

    if session["expires"] < time.time():

        sessions.pop(
            token,
            None
        )

        return None

    return {
        "token": token,
        **session
    }


def create_session():

    token = secrets.token_urlsafe(
        32
    )

    csrf = secrets.token_urlsafe(
        32
    )

    sessions[token] = {

        "csrf": csrf,

        "expires":
            time.time()
            + SESSION_TIME

    }

    return token, csrf


def logged_in(handler):

    return get_session(
        handler
    ) is not None


def csrf_valid(handler, form):

    session = get_session(
        handler
    )

    if not session:
        return False

    submitted = form.get(
        "csrf",
        [""]
    )[0]

    if not submitted:
        return False

    return hmac.compare_digest(
        submitted,
        session["csrf"]
    )


# =========================
# HTML
# =========================

def esc(value):

    value = str(
        value or ""
    )

    return (
        value
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def page(title, content):

    return f"""
<!DOCTYPE html>

<html lang="fa" dir="rtl">

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width,initial-scale=1">

<meta name="theme-color"
content="#050505">

<title>
سامانه غدیر | {esc(title)}
</title>

<style>

* {{
    box-sizing:border-box;
}}

body {{

    margin:0;

    min-height:100vh;

    font-family:
        Tahoma,
        Arial,
        sans-serif;

    color:#fff;

    background:
        radial-gradient(
            circle at top right,
            #493600 0,
            transparent 32%
        ),
        radial-gradient(
            circle at bottom left,
            #172554 0,
            transparent 35%
        ),
        linear-gradient(
            135deg,
            #020202,
            #0b0b0b,
            #111827
        );

}}

.container {{

    width:94%;

    max-width:1000px;

    margin:30px auto;

}}

.card {{

    background:
        rgba(17,17,17,.90);

    border:
        1px solid
        rgba(212,175,55,.25);

    border-radius:26px;

    padding:28px;

    margin-bottom:20px;

    box-shadow:
        0 20px 60px
        rgba(0,0,0,.45);

}}

.logo {{

    width:82px;

    height:82px;

    margin:0 auto 18px;

    border-radius:24px;

    display:flex;

    align-items:center;

    justify-content:center;

    font-size:40px;

    background:
        linear-gradient(
            135deg,
            #b8860b,
            #f5d76e,
            #8a6500
        );

    box-shadow:
        0 0 35px
        rgba(212,175,55,.30);

}}

h1 {{

    text-align:center;

    margin:5px 0 10px;

}}

h2 {{

    margin-top:0;

}}

.subtitle {{

    text-align:center;

    color:#aaa;

    line-height:2;

    margin-bottom:25px;

}}

input,
textarea,
select {{

    width:100%;

    padding:15px;

    margin-bottom:13px;

    border-radius:15px;

    border:
        1px solid
        rgba(255,255,255,.10);

    background:#171717;

    color:#fff;

    outline:none;

    font-size:16px;

}}

textarea {{

    min-height:190px;

    resize:vertical;

    line-height:1.9;

}}

input:focus,
textarea:focus,
select:focus {{

    border-color:#d4af37;

}}

button,
.btn {{

    display:block;

    width:100%;

    padding:15px;

    margin-top:8px;

    border:0;

    border-radius:15px;

    text-align:center;

    text-decoration:none;

    color:#fff;

    font-size:16px;

    font-weight:bold;

    cursor:pointer;

    background:
        linear-gradient(
            135deg,
            #b8860b,
            #d4af37,
            #8a6500
        );

}}

button:hover,
.btn:hover {{

    filter:brightness(1.12);

}}

.blue {{

    background:
        linear-gradient(
            135deg,
            #1d4ed8,
            #2563eb
        );

}}

.red {{

    background:
        linear-gradient(
            135deg,
            #991b1b,
            #dc2626
        );

}}

.green {{

    background:
        linear-gradient(
            135deg,
            #047857,
            #10b981
        );

}}

.gray {{

    background:
        linear-gradient(
            135deg,
            #374151,
            #4b5563
        );

}}

.back {{

    display:block;

    text-align:center;

    color:#e5c65b;

    text-decoration:none;

    margin-top:17px;

}}

.code {{

    padding:15px;

    margin:15px 0;

    border-radius:15px;

    text-align:center;

    color:#f5d76e;

    background:#050505;

    border:
        1px solid
        rgba(212,175,55,.25);

    font-weight:bold;

    letter-spacing:1px;

}}

.report {{

    padding:20px;

    margin-bottom:15px;

    border-radius:20px;

    background:#151515;

    border:
        1px solid
        rgba(255,255,255,.08);

}}

.status {{

    display:inline-block;

    padding:7px 12px;

    margin-bottom:10px;

    border-radius:999px;

    background:
        rgba(212,175,55,.15);

    color:#f5d76e;

}}

.text {{

    white-space:pre-wrap;

    line-height:2;

}}

.date {{

    color:#888;

    font-size:12px;

    margin-top:10px;

}}

.stats {{

    display:grid;

    grid-template-columns:
        repeat(3,1fr);

    gap:12px;

    margin-bottom:20px;

}}

.stat {{

    text-align:center;

    padding:18px;

    border-radius:18px;

    background:#151515;

    border:
        1px solid
        rgba(212,175,55,.15);

}}

.number {{

    font-size:30px;

    font-weight:bold;

    color:#f5d76e;

}}

.error {{

    padding:18px;

    border-radius:18px;

    background:#451a1a;

    border:
        1px solid #7f1d1d;

    text-align:center;

    margin-bottom:18px;

}}

.success {{

    padding:25px;

    border-radius:20px;

    background:#063b2b;

    border:
        1px solid #047857;

    text-align:center;

}}

@media(max-width:700px) {{

    .container {{
        width:92%;
        margin:18px auto;
    }}

    .card {{
        padding:20px;
        border-radius:22px;
    }}

    .stats {{
        grid-template-columns:1fr;
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
# صفحه اصلی
# =========================

def home():

    return page(
        "صفحه اصلی",
        """

<div class="card">

<div class="logo">
🛡️
</div>

<h1>
سامانه غدیر
</h1>

<div class="subtitle">

سامانه ثبت و پیگیری گزارش‌ها

<br>

گزارش خود را ثبت کنید و
با کد پیگیری وضعیت آن را مشاهده کنید.

</div>

<a class="btn" href="/report">
📝 ثبت گزارش
</a>

<a class="btn blue" href="/track">
🔎 پیگیری گزارش
</a>

<a class="btn gray" href="/admin">
🔐 ورود مدیریت
</a>

</div>

"""
    )


# =========================
# ثبت گزارش
# =========================

def report_page(message=""):

    error = ""

    if message:

        error = f"""
<div class="error">
{esc(message)}
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

{error}

<form method="POST"
action="/submit">

<input
type="password"
name="report_password"
placeholder="🔐 رمز ثبت گزارش"
required
>

<textarea
name="report"
maxlength="{MAX_REPORT_LENGTH}"
placeholder="✍️ گزارش خود را وارد کنید..."
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


# =========================
# نتیجه ثبت
# =========================

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
گزارش شما در سامانه ذخیره شد.
</p>

<div class="code">

کد پیگیری

<br><br>

{esc(code)}

</div>

<p>
این کد را برای پیگیری نگه دارید.
</p>

</div>

<a class="btn blue"
href="/track?code={urllib.parse.quote(code)}">

🔎 پیگیری همین گزارش

</a>

<a class="back"
href="/">

🏠 صفحه اصلی

</a>

</div>

"""
    )


# =========================
# پیگیری
# =========================

def track_page(message=""):

    error = ""

    if message:

        error = f"""
<div class="error">
{esc(message)}
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

<form method="GET"
action="/track">

<input
name="code"
placeholder="مثال: GHD-A1B2C3D4"
required
>

<button class="blue"
type="submit">

🔎 پیگیری

</button>

</form>

<a class="back"
href="/">

🏠 بازگشت

</a>

</div>

"""
    )


# =========================
# نتیجه پیگیری
# =========================

def track_result(code):

    url = (

        SUPABASE_URL
        + "/rest/v1/reports"
        + "?select=created_at,status,tracking_code"
        + "&tracking_code=eq."
        + urllib.parse.quote(
            code,
            safe=""
        )

    )

    reports = supabase_request(
        "GET",
        url
    )

    if not reports:

        return track_page(
            "گزارشی با این کد پیدا نشد."
        )

    item = reports[0]

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

🎫 {esc(code)}

</div>

<div
class="status"
style="margin-top:20px"
>

📌 وضعیت:

{esc(item.get("status","جدید"))}

</div>

<p class="date">

🕐 زمان ثبت:

{esc(item.get("created_at",""))}

</p>

<a class="back"
href="/track">

🔎 پیگیری دوباره

</a>

<a class="back"
href="/">

🏠 صفحه اصلی

</a>

</div>

"""
    )


# =========================
# ورود مدیر
# =========================

def admin_page():

    return page(
        "ورود مدیریت",
        """

<div class="card">

<div class="logo">
🔐
</div>

<h1>
ورود مدیریت
</h1>

<div class="subtitle">

رمز مدیریت را وارد کنید.

</div>

<form method="POST"
action="/login">

<input
type="password"
name="password"
placeholder="🔑 رمز مدیریت"
required
>

<button type="submit">

🚪 ورود

</button>

</form>

<a class="back"
href="/">

🏠 بازگشت

</a>

</div>

"""
    )


# =========================
# پنل مدیریت
# =========================

def admin_panel(handler):

    session = get_session(
        handler
    )

    url = (

        SUPABASE_URL
        + "/rest/v1/reports"
        + "?select=id,created_at,report,tracking_code,status"
        + "&order=created_at.desc"

    )

    reports = supabase_request(
        "GET",
        url
    ) or []

    total = len(reports)

    new_count = sum(
        1 for x in reports
        if x.get("status") == "جدید"
    )

    checked_count = sum(
        1 for x in reports
        if x.get("status") == "بررسی‌شده"
    )

    cards = ""

    for item in reports:

        report_id = str(
            item.get("id","")
        )

        code = item.get(
            "tracking_code",
            ""
        )

        status = item.get(
            "status",
            "جدید"
        )

        cards += f"""

<div class="report">

<div class="status">

📌 {esc(status)}

</div>

<div class="code">

🎫 {esc(code)}

</div>

<div class="text">

{esc(item.get("report",""))}

</div>

<div class="date">

🕐 {esc(item.get("created_at",""))}

</div>

<form
method="POST"
action="/status"
>

<input
type="hidden"
name="csrf"
value="{esc(session["csrf"])}"
>

<input
type="hidden"
name="id"
value="{esc(report_id)}"
>

<select name="status">

<option>
جدید
</option>

<option>
در حال بررسی
</option>

<option>
بررسی‌شده
</option>

</select>

<button class="green">

💾 تغییر وضعیت

</button>

</form>

<form
method="POST"
action="/delete"
>

<input
type="hidden"
name="csrf"
value="{esc(session["csrf"])}"
>

<input
type="hidden"
name="id"
value="{esc(report_id)}"
>

<button class="red">

🗑️ حذف گزارش

</button>

</form>

</div>

"""

    if not cards:

        cards = """

<div class="report"
style="text-align:center">

📭

<br><br>

هنوز گزارشی ثبت نشده است.

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

<div class="number">
{total}
</div>

کل گزارش‌ها

</div>

<div class="stat">

<div class="number">
{new_count}
</div>

جدید

</div>

<div class="stat">

<div class="number">
{checked_count}
</div>

بررسی‌شده

</div>

</div>

{cards}

<form method="POST"
action="/logout">

<input
type="hidden"
name="csrf"
value="{esc(session["csrf"])}"
>

<button class="gray">

🚪 خروج

</button>

</form>

<a class="back"
href="/">

🏠 صفحه اصلی

</a>

</div>

"""
    )


# =========================
# Handler
# =========================

class Handler(BaseHTTPRequestHandler):

    def send_html(
        self,
        content,
        status=200,
        cookies=None
    ):

        self.send_response(
            status
        )

        self.send_header(
            "Content-Type",
            "text/html; charset=utf-8"
        )

        self.send_header(
            "Cache-Control",
            "no-store"
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

        if cookies:

            for cookie in cookies:

                self.send_header(
                    "Set-Cookie",
                    cookie
                )

        self.end_headers()

        self.wfile.write(
            content.encode("utf-8")
        )


    def redirect(
        self,
        location,
        cookies=None
    ):

        self.send_response(
            302
        )

        self.send_header(
            "Location",
            location
        )

        if cookies:

            for cookie in cookies:

                self.send_header(
                    "Set-Cookie",
                    cookie
                )

        self.end_headers()


    def read_form(self):

        length = int(
            self.headers.get(
                "Content-Length",
                "0"
            )
        )

        body = self.rfile.read(
            length
        ).decode(
            "utf-8",
            errors="replace"
        )

        return urllib.parse.parse_qs(
            body
        )


    # =====================
    # GET
    # =====================

    def do_GET(self):

        parsed = urllib.parse.urlparse(
            self.path
        )

        path = parsed.path

        query = urllib.parse.parse_qs(
            parsed.query
        )

        try:

            if path == "/":

                self.send_html(
                    home()
                )

                return


            if path == "/report":

                self.send_html(
                    report_page()
                )

                return


            if path == "/track":

                code = query.get(
                    "code",
                    [""]
                )[0].strip()

                if code:

                    self.send_html(
                        track_result(
                            code
                        )
                    )

                else:

                    self.send_html(
                        track_page()
                    )

                return


            if path == "/admin":

                self.send_html(
                    admin_page()
                )

                return


            if path == "/reports":

                if not logged_in(
                    self
                ):

                    self.send_html(
                        page(
                            "خطا",
                            """
<div class="card">
<div class="error">
نشست معتبر نیست.
</div>
<a class="back" href="/admin">
بازگشت
</a>
</div>
"""
                        ),
                        403
                    )

                    return

                self.send_html(
                    admin_panel(
                        self
                    )
                )

                return


            self.send_html(
                page(
                    "404",
                    """
<div class="card">
<h1>404</h1>
<p>صفحه پیدا نشد.</p>
<a class="back" href="/">صفحه اصلی</a>
</div>
"""
                ),
                404
            )

        except Exception as e:

            print(
                "GET ERROR:",
                repr(e)
            )

            self.send_html(
                page(
                    "خطا",
                    f"""
<div class="card">
<div class="error">
خطایی رخ داد.
</div>
<p>{esc(e)}</p>
<a class="back" href="/">بازگشت</a>
</div>
"""
                ),
                500
            )


    # =====================
    # POST
    # =====================

    def do_POST(self):

        path = urllib.parse.urlparse(
            self.path
        ).path

        form = self.read_form()

        try:

            # ثبت گزارش
            if path == "/submit":

                password = form.get(
                    "report_password",
                    [""]
                )[0]

                if not REPORT_PASSWORD:

                    self.send_html(
                        report_page(
                            "رمز ثبت گزارش تنظیم نشده است."
                        )
                    )

                    return

                if not hmac.compare_digest(
                    password,
                    REPORT_PASSWORD
                ):

                    self.send_html(
                        report_page(
                            "رمز ثبت گزارش اشتباه است."
                        )
                    )

                    return

                report = form.get(
                    "report",
                    [""]
                )[0].strip()

                if not report:

  
