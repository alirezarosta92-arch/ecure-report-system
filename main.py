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

# =========================
# SETTINGS
# =========================

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
REPORT_PASSWORD = os.environ.get("REPORT_PASSWORD", "")

SUPABASE_URL = os.environ.get(
    "SUPABASE_URL",
    ""
).rstrip("/")

SUPABASE_SECRET_KEY = os.environ.get(
    "SUPABASE_SECRET_KEY",
    ""
)

PORT = int(
    os.environ.get(
        "PORT",
        8080
    )
)

SESSION_TTL = 3600

SESSIONS = {}


# =========================
# SECURITY
# =========================

def cookies(handler):

    result = {}

    for part in handler.headers.get(
        "Cookie",
        ""
    ).split(";"):

        if "=" in part:

            key, value = part.strip().split(
                "=",
                1
            )

            result[key] = value

    return result


def get_session(handler):

    token = cookies(handler).get(
        "session"
    )

    data = SESSIONS.get(token)

    if not data:
        return None

    if data["expires"] < time.time():

        SESSIONS.pop(
            token,
            None
        )

        return None

    return data


def new_session():

    token = secrets.token_urlsafe(
        32
    )

    csrf = secrets.token_urlsafe(
        32
    )

    SESSIONS[token] = {
        "csrf": csrf,
        "expires": time.time() + SESSION_TTL
    }

    return token, csrf


def make_cookie(
    name,
    value,
    age=SESSION_TTL,
    http_only=True
):

    text = (
        f"{name}={value}; "
        "Path=/; "
        "SameSite=Strict; "
        "Secure; "
        f"Max-Age={age}"
    )

    if http_only:
        text += "; HttpOnly"

    return text


def csrf_ok(handler, form):

    current = get_session(
        handler
    )

    if not current:
        return False

    submitted = form.get(
        "csrf",
        [""]
    )[0]

    stored = current["csrf"]

    browser = cookies(handler).get(
        "csrf",
        ""
    )

    return (
        bool(submitted)
        and bool(browser)
        and hmac.compare_digest(
            submitted,
            stored
        )
        and hmac.compare_digest(
            browser,
            stored
        )
    )


# =========================
# SUPABASE
# =========================

def supabase(
    method,
    endpoint,
    data=None
):

    headers = {
        "apikey": SUPABASE_SECRET_KEY,
        "Authorization":
            "Bearer " + SUPABASE_SECRET_KEY,
        "Content-Type":
            "application/json",
        "Prefer":
            "return=minimal"
    }

    body = None

    if data is not None:

        body = json.dumps(
            data,
            ensure_ascii=False
        ).encode(
            "utf-8"
        )

    request = urllib.request.Request(

        SUPABASE_URL + endpoint,

        data=body,

        headers=headers,

        method=method
    )

    try:

        with urllib.request.urlopen(
            request,
            timeout=15
        ) as response:

            text = response.read().decode(
                "utf-8"
            )

            if text:
                return json.loads(text)

            return None

    except urllib.error.HTTPError as error:

        error_text = error.read().decode(
            "utf-8",
            errors="replace"
        )

        print(
            "SUPABASE ERROR:",
            error_text
        )

        raise Exception(
            f"Supabase HTTP {error.code}: "
            f"{error_text}"
        )


# =========================
# HTML / CSS
# =========================

CSS = """
<style>

* {
    box-sizing: border-box;
}

body {

    margin: 0;

    font-family:
        Tahoma,
        Arial,
        sans-serif;

    direction: rtl;

    color: white;

    min-height: 100vh;

    background:

        radial-gradient(
            circle at 15% 20%,
            #1d4ed855,
            transparent 30%
        ),

        radial-gradient(
            circle at 85% 80%,
            #7c3aed55,
            transparent 30%
        ),

        linear-gradient(
            135deg,
            #020617,
            #0f172a
        );
}

.container {

    width: 92%;

    max-width: 900px;

    margin: 45px auto;
}

.card {

    background:
        #0f172ae8;

    border:
        1px solid #ffffff15;

    border-radius: 28px;

    padding: 30px;

    box-shadow:
        0 25px 70px #0008;

    backdrop-filter:
        blur(15px);

    margin-bottom: 20px;
}

.logo {

    width: 82px;

    height: 82px;

    border-radius: 25px;

    margin: auto;

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
        0 15px 40px #2563eb55;
}

h1 {

    text-align: center;

    margin:
        18px 0 8px;
}

h2 {

    margin-top: 5px;
}

.subtitle {

    text-align: center;

    color: #94a3b8;

    line-height: 2;

    margin-bottom: 25px;
}

input,
textarea,
select {

    width: 100%;

    padding: 15px;

    margin: 7px 0;

    border-radius: 15px;

    border:
        1px solid #ffffff12;

    background:
        #1e293bcc;

    color: white;

    font-size: 16px;

    outline: none;

    font-family:
        Tahoma,
        Arial,
        sans-serif;
}

input:focus,
textarea:focus,
select:focus {

    border-color:
        #3b82f6;

    box-shadow:
        0 0 0 3px
        #3b82f633;
}

textarea {

    min-height: 170px;

    resize: vertical;

    line-height: 1.8;
}

button {

    width: 100%;

    padding: 15px;

    margin-top: 10px;

    border: 0;

    border-radius: 15px;

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

    transition:
        .2s;
}

button:hover {

    filter:
        brightness(1.1);

    transform:
        translateY(-1px);
}

.danger {

    background:
        linear-gradient(
            135deg,
            #dc2626,
            #991b1b
        );
}

.green {

    background:
        linear-gradient(
            135deg,
            #059669,
            #047857
        );
}

.gray {

    background:
        linear-gradient(
            135deg,
            #475569,
            #334155
        );
}

a {

    display: block;

    text-align: center;

    color: #93c5fd;

    text-decoration: none;

    margin-top: 18px;
}

.success,
.error {

    padding: 20px;

    border-radius: 18px;

    text-align: center;

    margin-bottom: 20px;
}

.success {

    background:
        #166534aa;

    border:
        1px solid #22c55e22;
}

.error {

    background:
        #991b1baa;

    border:
        1px solid #ef444422;
}

.report {

    padding: 20px;

    border-radius: 20px;

    background:
        #1e293bcc;

    margin: 15px 0;

    border:
        1px solid #ffffff10;
}

.code {

    padding: 14px;

    margin: 12px 0;

    border-radius: 14px;

    background:
        #020617;

    text-align: center;

    color: #bfdbfe;

    font-weight: bold;

    letter-spacing: 1px;
}

.stats {

    display: grid;

    grid-template-columns:
        repeat(3, 1fr);

    gap: 12px;

    margin-bottom: 20px;
}

.stat {

    background:
        #1e293baa;

    padding: 18px;

    border-radius: 18px;

    text-align: center;
}

.number {

    font-size: 28px;

    font-weight: bold;

    color: #bfdbfe;

    margin-bottom: 5px;
}

@media(max-width:650px) {

    .container {

        margin:
            20px auto;
    }

    .card {

        padding: 20px;

        border-radius: 22px;
    }

    .stats {

        grid-template-columns:
            1fr;
    }
}

</style>
"""


def page(title, body):

    return f"""
<!DOCTYPE html>

<html lang="fa" dir="rtl">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width,initial-scale=1"
>

<title>
{html.escape(title)}
</title>

{CSS}

</head>

<body>

<div class="container">

{body}

</div>

</body>

</html>
"""


# =========================
# LOGIN
# =========================

def login_page(message=""):

    error = ""

    if message:

        error = f"""
<div class="error">
{html.escape(message)}
</div>
"""

    return page(
        "ورود سامانه",
        f"""

<div class="card">

<div class="logo">
🔐
</div>

<h1>
ورود به سامانه غدیر
</h1>

<div class="subtitle">

برای ورود، نام کاربری و
رمز عبور خود را وارد کنید.

</div>

{error}

<form
    method="POST"
    action="/login"
>

<input
    name="username"
    placeholder="👤 نام کاربری"
    autocomplete="username"
    required
>

<input
    type="password"
    name="password"
    placeholder="🔑 رمز عبور"
    autocomplete="current-password"
    required
>

<button type="submit">

🚀 ورود

</button>

</form>

</div>

"""
    )


# =========================
# HOME
# =========================

def home_page():

    return page(
        "سامانه غدیر",
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

</div>

<a href="/report">

<button>
📝 ثبت گزارش
</button>

</a>

<a href="/track">

<button class="green">
🔎 پیگیری گزارش
</button>

</a>

<a href="/reports">

<button>
📋 پنل مدیریت
</button>

</a>

<form
    method="POST"
    action="/logout"
>

<input
    type="hidden"
    name="csrf"
    value="{html.escape(
        get_current_csrf_placeholder()
    )}"
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


# =========================
# CSRF PLACEHOLDER HELPER
# =========================

def get_current_csrf_placeholder():

    return ""


def home_page_for_session(handler):

    current = get_session(handler)

    csrf = ""

    if current:
        csrf = current["csrf"]

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

<a href="/report">
<button>
📝 ثبت گزارش
</button>
</a>

<a href="/track">
<button class="green">
🔎 پیگیری گزارش
</button>
</a>

<a href="/reports">
<button>
📋 پنل مدیریت
</button>
</a>

<form
    method="POST"
    action="/logout"
>

<input
    type="hidden"
    name="csrf"
    value="{html.escape(csrf)}"
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


# =========================
# REPORT PAGE
# =========================

def report_page(message=""):

    error = ""

    if message:

        error = f"""
<div class="error">
{html.escape(message)}
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
گزارش خود را وارد کنید.
</div>

{error}

<form
    method="POST"
    action="/submit"
>

<input
    type="password"
    name="report_password"
    placeholder="🔐 رمز ثبت گزارش"
    required
>

<textarea
    name="report"
    placeholder="✍️ گزارش خود را بنویسید..."
    required
></textarea>

<button type="submit">

🚀 ثبت گزارش

</button>

</form>

<a href="/">
🏠 بازگشت
</a>

</div>

"""
    )


# =========================
# TRACK PAGE
# =========================

def track_page(message=""):

    error = ""

    if message:

        error = f"""
<div class="error">
{html.escape(message)}
</div>
"""

    return page(
        "پیگیری",
        f"""

<div class="card">

<div class="logo">
🔎
</div>

<h1>
پیگیری گزارش
</h1>

<div class="subtitle">

کد پیگیری گزارش را وارد کنید.

</div>

{error}

<form
    method="GET"
    action="/track"
>

<input
    name="code"
    placeholder="🎫 کد پیگیری"
    required
>

<button type="submit">

🔎 پیگیری

</button>

</form>

<a href="/">
🏠 بازگشت
</a>

</div>

"""
    )


# =========================
# TRACK RESULT
# =========================

def track_result(code):

    endpoint = (

        "/rest/v1/reports"

        "?select=created_at,status,tracking_code"

        "&tracking_code=eq."

        + quote(
            code,
            safe=""
        )
    )

    rows = supabase(
        "GET",
        endpoint
    )

    if not rows:

        return track_page(
            "گزارشی با این کد پیدا نشد."
        )

    item = rows[0]

    tracking_code = html.escape(
        str(
            item.get(
                "tracking_code",
                ""
            )
        )
    )

    status = html.escape(
        str(
            item.get(
                "status",
                "جدید"
            )
        )
    )

    created = html.escape(
        str(
            item.get(
                "created_at",
                ""
            )
        )
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

{tracking_code}

</div>

<div class="success">

<h2>

وضعیت:
{status}

</h2>

زمان ثبت:

<br>

{created}

</div>

<a href="/track">
🔎 پیگیری دوباره
</a>

<a href="/">
🏠 صفحه اصلی
</a>

</div>

"""
    )


# =========================
# REPORTS PAGE
# =========================

def reports_page(
    search="",
    csrf_token=""
):

    endpoint = (

        "/rest/v1/reports"

        "?select=id,created_at,report,tracking_code,status"

        "&order=created_at.desc"
    )

    rows = supabase(
        "GET",
        endpoint
    )

    search = search.strip().lower()

    if search:

        rows = [

            item

            for item in rows

            if (

                search
                in str(
                    item.get(
                        "report",
                        ""
                    )
                ).lower()

                or

                search
                in str(
                    item.get(
                        "tracking_code",
                        ""
                    )
                ).lower()

                or

                search
                in str(
                    item.get(
                        "status",
                        ""
                    )
                ).lower()
            )
        ]

    total = len(rows)

    new_count = sum(

        item.get(
            "status",
            "جدید"
        ) == "جدید"

        for item in rows
    )

    checked_count = sum(

        item.get(
            "status",
            ""
        ) == "بررسی‌شده"

        for item in rows
    )

    checking_count = sum(

        item.get(
            "status",
            ""
        ) == "در حال بررسی"

        for item in rows
    )

    cards = ""

    for item in rows:

        report_id = str(
            item.get(
                "id",
                ""
            )
        )

        code = str(
            item.get(
                "tracking_code",
                ""
            )
        )

        status = str(
            item.get(
                "status",
                "جدید"
            )
        )

        report_text = str(
            item.get(
                "report",
                ""
            )
        )

        created = str(
            item.get(
                "created_at",
                ""
            )
        )

        cards += f"""

<div class="report">

<div class="code">

🎫

{html.escape(code)}

</div>

<p style="line-height:2">

{html.escape(report_text)}

</p>

<p style="color:#94a3b8">

🕐

{html.escape(created)}

</p>

<div class="success">

وضعیت فعلی:

<br>

<strong>

{html.escape(status)}

</strong>

</div>

<form
    method="POST"
    action="/status"
>

<input
    type="hidden"
    name="id"
    value="{html.escape(report_id)}"
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

<input
    type="hidden"
    name="csrf"
    value="{html.escape(csrf_token)}"
>

<button
    class="green"
    type="submit"
>

💾 تغییر وضعیت

</button>

</form>

<form
    method="POST"
    action="/delete"
>

<input
    type="hidden"
    name="id"
    value="{html.escape(report_id)}"
>

<input
    type="hidden"
    name="csrf"
    value="{html.escape(csrf_token)}"
>

<button
    class="danger"
    type="submit"
>

🗑️ حذف گزارش

</button>

</form>

</div>

"""

    if not cards:

        cards = """

<div class="error">

📭

<br><br>

گزارشی پیدا نشد.

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

گزارش جدید

</div>

<div class="stat">

<div class="number">
{checked_count}
</div>

بررسی‌شده

</div>

</div>

<div class="stat">

<div class="number">
{checking_count}
</div>

در حال بررسی

</div>

<br>

<form
    method="GET"
    action="/reports"
>

<input
    name="search"
    value="{html.escape(search)}"
    placeholder="🔎 جست‌وجو در گزارش‌ها..."
>

<button type="submit">

🔍 جست‌وجو

</button>

</form>

{cards}

<form
    method="POST"
    action="/logout"
>

<input
    type="hidden"
    name="csrf"
    value="{html.escape(csrf_token)}"
>

<button
    class="gray"
    type="submit"
>

🚪 خروج

</button>

</form>

<a href="/">
🏠 صفحه اصلی
</a>

</div>

"""
    )


# =========================
# SERVER
# =========================

class Server(
    BaseHTTPRequestHandler
):


    # =====================
    # SEND HTML
    # =====================

    def send_html(
        self,
        text,
        status=200,
        extra=None
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

        if extra:

            for key, value in extra:

                self.send_header(
                    key,
                    value
                )

        self.end_headers()

        self.wfile.write(
            text.encode(
                "utf-8"
            )
        )


    # =====================
    # GET
    # =====================

    def do_GET(self):

        parsed = urlparse(
            self.path
        )

        path = parsed.path

        query = parse_qs(
            parsed.query
        )

        try:

            # HOME

            if path == "/":

                if get_session(self):

                    self.send_html(
                        home_page_for_session(
                            self
                        )
                    )

                else:

                    self.send_html(
                        login_page()
                    )

                return


            # ADMIN

            if path == "/admin":

                if get_session(self):

                    self.send_html(
                        home_page_for_session(
                            self
                        )
                    )

                else:

                    self.send_html(
                        login_page()
                    )

                return


            # REPORT

            if path == "/report":

                if not get_session(self):

                    self.send_html(
                        login_page(
                            "ابتدا وارد حساب شوید."
             
