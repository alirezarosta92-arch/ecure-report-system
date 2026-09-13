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
# تنظیمات
# =========================

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
REPORT_PASSWORD = os.environ.get("REPORT_PASSWORD", "")
SUPABASE_URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
SUPABASE_SECRET_KEY = os.environ.get("SUPABASE_SECRET_KEY", "")

PORT = int(os.environ.get("PORT", 8080))

SESSION_COOKIE_NAME = "session"
CSRF_COOKIE_NAME = "csrf_token"
SESSION_TTL = int(os.environ.get("SESSION_TTL", 3600))
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "1") != "0"

SESSIONS = {}


# =========================
# مدیریت نشست و CSRF
# =========================

def cookie_attributes(max_age=None):
    attributes = [
        "Path=/",
        "HttpOnly",
        "SameSite=Strict"
    ]

    if COOKIE_SECURE:
        attributes.append("Secure")

    if max_age is not None:
        attributes.append(f"Max-Age={max_age}")

    return "; ".join(attributes)


def parse_cookies(header):
    cookies = {}

    for part in (header or "").split(";"):
        if "=" not in part:
            continue

        name, value = part.strip().split("=", 1)
        cookies[name] = value

    return cookies


def get_session(handler):
    cookies = parse_cookies(
        handler.headers.get("Cookie", "")
    )

    token = cookies.get(SESSION_COOKIE_NAME)

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


def create_session():
    session_token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)

    SESSIONS[session_token] = {
        "csrf_token": csrf_token,
        "expires_at": time.time() + SESSION_TTL
    }

    return session_token, csrf_token


def delete_session(token):
    if token:
        SESSIONS.pop(token, None)


def is_logged_in(handler):
    return get_session(handler) is not None


def csrf_is_valid(handler, info):
    session = get_session(handler)

    if not session:
        return False

    submitted_token = info.get(
        "csrf_token",
        [""]
    )[0]

    cookie_token = parse_cookies(
        handler.headers.get("Cookie", "")
    ).get(CSRF_COOKIE_NAME, "")

    expected_token = session["csrf_token"]

    return (
        bool(submitted_token)
        and bool(cookie_token)
        and hmac.compare_digest(submitted_token, expected_token)
        and hmac.compare_digest(cookie_token, expected_token)
    )


def csrf_field(handler):
    session = get_session(handler)

    if not session:
        return ""

    return f"""
<input
type="hidden"
name="csrf_token"
value="{html.escape(session["csrf_token"])}"
>
"""


def reject_request(handler, status=403, message="درخواست غیرمجاز است."):
    handler.send_response(status)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(
        error_page(message).encode("utf-8")
    )


# =========================
# اتصال به Supabase
# =========================

def supabase_request(method, url, data=None):

    headers = {
        "apikey": SUPABASE_SECRET_KEY,
        "Authorization": "Bearer " + SUPABASE_SECRET_KEY,
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

        with urllib.request.urlopen(request, timeout=15) as response:

            text = response.read().decode("utf-8")

            if text:
                return json.loads(text)

            return None

    except urllib.error.HTTPError as e:

        error_body = e.read().decode(
            "utf-8",
            errors="replace"
        )

        print("SUPABASE ERROR:", error_body)

        raise Exception(
            f"Supabase HTTP {e.code}: {error_body}"
        )


# =========================
# قالب اصلی سایت
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

<title>{html.escape(title)}</title>


<style>

/* =========================
   Reset
========================= */

* {{
    box-sizing: border-box;
}}

html {{
    scroll-behavior: smooth;
}}

body {{

    margin: 0;

    min-height: 100vh;

    font-family:
        Tahoma,
        Arial,
        sans-serif;

    color: #ffffff;

    background:

        radial-gradient(
            circle at 10% 20%,
            rgba(37,99,235,.22),
            transparent 30%
        ),

        radial-gradient(
            circle at 90% 80%,
            rgba(124,58,237,.22),
            transparent 30%
        ),

        linear-gradient(
            135deg,
            #020617,
            #071127,
            #0f172a
        );

    overflow-x: hidden;
}}


/* =========================
   Background
========================= */

body::before {{

    content: "";

    position: fixed;

    width: 280px;
    height: 280px;

    border-radius: 50%;

    background: rgba(59,130,246,.10);

    filter: blur(70px);

    top: -100px;
    right: -80px;

    pointer-events: none;
}}

body::after {{

    content: "";

    position: fixed;

    width: 300px;
    height: 300px;

    border-radius: 50%;

    background: rgba(168,85,247,.10);

    filter: blur(80px);

    bottom: -120px;
    left: -100px;

    pointer-events: none;
}}


/* =========================
   Container
========================= */

.container {{

    width: 94%;

    max-width: 1050px;

    margin: 35px auto;

    position: relative;

    z-index: 1;
}}


/* =========================
   Card
========================= */

.card {{

    background:
        linear-gradient(
            145deg,
            rgba(30,41,59,.92),
            rgba(15,23,42,.94)
        );

    border: 1px solid rgba(255,255,255,.08);

    border-radius: 28px;

    padding: 30px;

    margin-bottom: 22px;

    box-shadow:
        0 25px 70px rgba(0,0,0,.35),
        inset 0 1px 0 rgba(255,255,255,.04);

    backdrop-filter: blur(16px);

    animation: cardIn .45s ease;
}}

@keyframes cardIn {{

    from {{
        opacity: 0;
        transform: translateY(15px);
    }}

    to {{
        opacity: 1;
        transform: translateY(0);
    }}
}}


/* =========================
   Header
========================= */

.logo-box {{

    width: 82px;
    height: 82px;

    margin: 0 auto 18px;

    border-radius: 24px;

    display: flex;

    align-items: center;

    justify-content: center;

    font-size: 42px;

    background:

        linear-gradient(
            135deg,
            #2563eb,
            #7c3aed
        );

    box-shadow:
        0 15px 35px rgba(37,99,235,.30);

}}

h1 {{

    text-align: center;

    font-size: 30px;

    margin: 5px 0 10px;

}}

h2 {{

    margin-top: 0;

}}

.subtitle {{

    text-align: center;

    color: #94a3b8;

    font-size: 15px;

    line-height: 1.8;

    margin-bottom: 28px;
}}


/* =========================
   Inputs
========================= */

input,
textarea,
select {{

    width: 100%;

    border: 1px solid rgba(255,255,255,.08);

    outline: none;

    border-radius: 16px;

    padding: 15px 17px;

    font-size: 16px;

    background: rgba(51,65,85,.75);

    color: white;

    margin-bottom: 13px;

    font-family:
        Tahoma,
        Arial,
        sans-serif;

    transition: .2s;
}}

input:focus,
textarea:focus,
select:focus {{

    border-color: #3b82f6;

    box-shadow:
        0 0 0 3px rgba(59,130,246,.15);
}}

textarea {{

    min-height: 190px;

    resize: vertical;

    line-height: 1.8;
}}

input::placeholder,
textarea::placeholder {{

    color: #94a3b8;
}}


/* =========================
   Buttons
========================= */

button {{

    width: 100%;

    border: none;

    border-radius: 16px;

    padding: 15px;

    margin-top: 7px;

    font-size: 16px;

    font-weight: bold;

    cursor: pointer;

    color: white;

    background:
        linear-gradient(
            135deg,
            #2563eb,
            #4f46e5
        );

    box-shadow:
        0 10px 25px rgba(37,99,235,.20);

    transition:
        transform .2s,
        box-shadow .2s,
        filter .2s;
}}

button:hover {{

    transform: translateY(-2px);

    filter: brightness(1.08);

    box-shadow:
        0 15px 30px rgba(37,99,235,.28);
}}

button:active {{

    transform: translateY(0);
}}

.delete {{

    background:
        linear-gradient(
            135deg,
            #dc2626,
            #991b1b
        );
}}

.status-button {{

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


/* =========================
   Links
========================= */

.back {{

    display: block;

    text-align: center;

    color: #93c5fd;

    text-decoration: none;

    margin-top: 17px;

    transition: .2s;
}}

.back:hover {{

    color: white;

    transform: translateY(-1px);
}}


/* =========================
   Feature Cards
========================= */

.features {{

    display: grid;

    grid-template-columns:
        repeat(3, 1fr);

    gap: 13px;

    margin-top: 25px;
}}

.feature {{

    padding: 18px;

    border-radius: 18px;

    background:
        rgba(51,65,85,.48);

    border:
        1px solid rgba(255,255,255,.06);

    text-align: center;
}}

.feature-icon {{

    font-size: 27px;

    margin-bottom: 7px;
}}

.feature-title {{

    font-weight: bold;

    margin-bottom: 5px;
}}

.feature-text {{

    color: #94a3b8;

    font-size: 12px;

    line-height: 1.6;
}}


/* =========================
   Success / Error
========================= */

.success {{

    background:
        linear-gradient(
            135deg,
            rgba(22,101,52,.85),
            rgba(21,128,61,.55)
        );

    border:
        1px solid rgba(74,222,128,.20);

    padding: 24px;

    border-radius: 20px;

    text-align: center;
}}

.error {{

    background:
        linear-gradient(
            135deg,
            rgba(153,27,27,.85),
            rgba(127,29,29,.60)
        );

    border:
        1px solid rgba(248,113,113,.20);

    padding: 20px;

    border-radius: 18px;

    text-align: center;

    word-break: break-word;
}}


/* =========================
   Report
========================= */

.report {{

    background:
        linear-gradient(
            145deg,
            rgba(51,65,85,.82),
            rgba(30,41,59,.82)
        );

    border:
        1px solid rgba(255,255,255,.07);

    border-radius: 21px;

    padding: 21px;

    margin-bottom: 16px;

    transition: .2s;
}}

.report:hover {{

    transform: translateY(-2px);

    border-color:
        rgba(96,165,250,.25);
}}

.report-text {{

    white-space: pre-wrap;

    line-height: 2;

    margin: 15px 0;

    color: #f8fafc;
}}

.date {{

    color: #94a3b8;

    font-size: 12px;

    margin-top: 10px;
}}


/* =========================
   Tracking Code
========================= */

.code {{

    background:
        rgba(2,6,23,.75);

    border:
        1px solid rgba(96,165,250,.15);

    border-radius: 14px;

    padding: 14px;

    text-align: center;

    font-weight: bold;

    letter-spacing: 1.5px;

    margin: 13px 0;

    color: #bfdbfe;
}}


/* =========================
   Badge
========================= */

.badge {{

    display: inline-block;

    padding: 7px 13px;

    border-radius: 999px;

    background:
        rgba(37,99,235,.20);

    border:
        1px solid rgba(96,165,250,.18);

    color: #bfdbfe;

    margin-bottom: 8px;

    font-size: 13px;
}}


/* =========================
   Stats
========================= */

.stats {{

    display: grid;

    grid-template-columns:
        repeat(3, 1fr);

    gap: 13px;

    margin-bottom: 22px;
}}

.stat {{

    background:
        linear-gradient(
            145deg,
            rgba(51,65,85,.70),
            rgba(30,41,59,.70)
        );

    border-radius: 18px;

    padding: 18px;

    text-align: center;

    border:
        1px solid rgba(255,255,255,.06);
}}

.stat-number {{

    font-size: 30px;

    font-weight: bold;

    margin-bottom: 5px;

    color: #bfdbfe;
}}


/* =========================
   Search
========================= */

.search-box {{

    margin-bottom: 22px;
}}


/* =========================
   Responsive
========================= */

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

    .features {{
        grid-template-columns: 1fr;
    }}

    .stats {{
        grid-template-columns: 1fr;
    }}

    textarea {{
        min-height: 160px;
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

def main_page():

    return page(
        "سامانه غدیر",
        """

<div class="card">

<div class="logo-box">
🛡️
</div>

<h1>
سامانه غدیر
</h1>

<div class="subtitle">

سامانه ثبت و پیگیری گزارش‌ها

<br>

گزارش خود را ثبت کنید و با کد پیگیری
وضعیت آن را مشاهده کنید.

</div>


<form method="POST" action="/report">

<input
type="password"
name="report_password"
placeholder="🔐 رمز ثبت گزارش"
required
>

<textarea
name="report"
placeholder="✍️ گزارش خود را اینجا بنویسید..."
required
></textarea>

<button type="submit">
🚀 ثبت گزارش
</button>

</form>


<div class="features">

<div class="feature">

<div class="feature-icon">
🔐
</div>

<div class="feature-title">
محافظت‌شده
</div>

<div class="feature-text">
ثبت گزارش با رمز ورود
</div>

</div>


<div class="feature">

<div class="feature-icon">
🎫
</div>

<div class="feature-title">
کد پیگیری
</div>

<div class="feature-text">
هر گزارش دارای کد اختصاصی
</div>

</div>


<div class="feature">

<div class="feature-icon">
🔎
</div>

<div class="feature-title">
پیگیری آنلاین
</div>

<div class="feature-text">
مشاهده وضعیت گزارش
</div>

</div>

</div>


<a class="back" href="/track">
🔎 پیگیری گزارش
</a>

<a class="back" href="/admin">
🔐 ورود مدیریت
</a>

</div>

"""
    )


# =========================
# صفحه موفقیت
# =========================

def success_page(code):

    return page(
        "گزارش ثبت شد",
        f"""

<div class="card">

<div class="success">

<div style="font-size:50px;">
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

<span style="font-size:22px;">
{html.escape(code)}
</span>

</div>


<p style="color:#bbf7d0;">
این کد را برای پیگیری گزارش نگه دارید.
</p>

</div>


<a class="back" href="/track">
🔎 پیگیری گزارش
</a>

<a class="back" href="/">
🏠 بازگشت به صفحه اصلی
</a>

</div>

"""
    )


# =========================
# صفحه خطا
# =========================

def error_page(error_text):

    return page(
        "خطا",
        f"""

<div class="card">

<div class="error">

<div style="font-size:45px;">
❌
</div>

<h2>
عملیات ناموفق بود
</h2>

<p>
{html.escape(str(error_text))}
</p>

</div>


<a class="back" href="/">
🏠 بازگشت
</a>

</div>

"""
    )


# =========================
# صفحه ورود مدیریت
# =========================

def admin_login_page():

    return page(
        "ورود مدیریت",
        """

<div class="card">

<div class="logo-box">
🔐
</div>

<h1>
ورود مدیریت
</h1>

<div class="subtitle">
برای ورود به پنل مدیریت رمز خود را وارد کنید.
</div>


<form method="POST" action="/login">

<input
type="password"
name="password"
placeholder="🔑 رمز مدیریت"
required
>

<button type="submit">
🚪 ورود به پنل
</button>

</form>


<a class="back" href="/">
🏠 بازگشت
</a>

</div>

"""
    )


# =========================
# پنل گزارش‌ها
# =========================

def reports_page(search="", csrf_token=""):

    url = (

        SUPABASE_URL

        + "/rest/v1/reports"

        + "?select=id,created_at,report,tracking_code,status"

        + "&order=created_at.desc"

    )


    reports = supabase_request(
        "GET",
        url
    )


    search = search.strip().lower()


    if search:

        reports = [

            item

            for item in reports

            if

            search in str(
                item.get(
                    "report",
                    ""
                )
            ).lower()

            or

            search in str(
                item.get(
                    "tracking_code",
                    ""
                )
            ).lower()

            or

            search in str(
                item.get(
                    "status",
                    ""
                )
            ).lower()

        ]


    total = len(reports)


    new_count = sum(

        1

        for x in reports

        if x.get(
            "status",
            "جدید"
        ) == "جدید"

    )


    checking_count = sum(

        1

        for x in reports

        if x.get(
            "status",
            ""
        ) == "در حال بررسی"

    )


    checked_count = sum(

        1

        for x in reports

        if x.get(
            "status",
            ""
        ) == "بررسی‌شده"

    )


    reports_html = ""


    for item in reports:

        report_id = str(
            item.get(
                "id",
                ""
            )
        )


        report_text = html.escape(
            str(
                item.get(
                    "report",
                    ""
                )
            )
        )


        created_at = html.escape(
            str(
                item.get(
                    "created_at",
                    ""
                )
            )
        )


        tracking_code = html.escape(
            str(
                item.get(
                    "tracking_code",
                    ""
                )
            )
        )


        if not tracking_code:

            tracking_code = (
                "GHD-"
                + report_id
            )


        status = html.escape(
            str(
                item.get(
                    "status",
                    "جدید"
                )
            )
        )


        reports_html += f"""

<div class="report">

<div class="badge">
📌 وضعیت: {status}
</div>


<div class="code">

🎫 کد پیگیری

<br>

{tracking_code}

</div>


<div class="report-text">
{report_text}
</div>


<div class="date">

🕐 زمان ثبت:

{created_at}

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


<button
class="status-button"
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
name="csrf_token"
value="{html.escape(csrf_token)}"
>


<button
class="delete"
type="submit"
>

🗑️ حذف گزارش

</button>

</form>

</div>

"""


    if not reports_html:

        reports_html = """

<div class="card"
style="text-align:center;color:#94a
