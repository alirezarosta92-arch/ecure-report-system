from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse, quote
import urllib.request
import urllib.error
import json
import html
import os
import secrets
import hmac

# =========================
# تنظیمات
# =========================

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
REPORT_PASSWORD = os.environ.get("REPORT_PASSWORD", "")

SUPABASE_URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
SUPABASE_SECRET_KEY = os.environ.get("SUPABASE_SECRET_KEY", "")

PORT = int(os.environ.get("PORT", 8080))

SESSION_TOKEN = secrets.token_urlsafe(32)


# =========================
# Supabase
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

        with urllib.request.urlopen(
            request,
            timeout=15
        ) as response:

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

<title>{html.escape(title)}</title>

<style>

* {{
box-sizing:border-box;
}}

body {{

margin:0;

font-family:
Tahoma,
Arial,
sans-serif;

background:
linear-gradient(
135deg,
#020617,
#0f172a,
#172554
);

color:white;

min-height:100vh;

}}

.container {{

width:94%;

max-width:900px;

margin:30px auto;

}}

.card {{

background:
rgba(30,41,59,.95);

border-radius:22px;

padding:24px;

margin-bottom:20px;

box-shadow:
0 15px 40px
rgba(0,0,0,.35);

}}

h1 {{

text-align:center;

margin-bottom:25px;

}}

input,
textarea,
select {{

width:100%;

border:none;

outline:none;

border-radius:13px;

padding:14px;

font-size:16px;

background:#334155;

color:white;

margin-bottom:12px;

font-family:
Tahoma,
Arial,
sans-serif;

}}

textarea {{

min-height:180px;

resize:vertical;

}}

button {{

width:100%;

border:none;

border-radius:13px;

padding:14px;

margin-top:8px;

font-size:16px;

cursor:pointer;

background:#2563eb;

color:white;

}}

button:hover {{

background:#1d4ed8;

}}

.delete {{

background:#dc2626;

}}

.status-button {{

background:#16a34a;

}}

.logout {{

background:#475569;

}}

.success {{

background:#166534;

padding:18px;

border-radius:14px;

text-align:center;

}}

.error {{

background:#991b1b;

padding:18px;

border-radius:14px;

text-align:center;

word-break:break-word;

}}

.report {{

background:#334155;

border-radius:17px;

padding:18px;

margin-bottom:16px;

}}

.report-text {{

white-space:pre-wrap;

line-height:1.9;

margin:15px 0;

}}

.date {{

color:#cbd5e1;

font-size:13px;

}}

.code {{

background:#0f172a;

border-radius:10px;

padding:12px;

text-align:center;

font-weight:bold;

letter-spacing:1px;

margin:10px 0;

}}

.badge {{

display:inline-block;

padding:7px 12px;

border-radius:20px;

background:#2563eb;

margin-bottom:8px;

}}

.back {{

display:block;

text-align:center;

color:#93c5fd;

margin-top:18px;

text-decoration:none;

}}

.stats {{

display:grid;

grid-template-columns:
repeat(3,1fr);

gap:10px;

margin-bottom:20px;

}}

.stat {{

background:#334155;

border-radius:15px;

padding:15px;

text-align:center;

}}

.stat-number {{

font-size:26px;

font-weight:bold;

}}

@media(max-width:600px) {{

.stats {{

grid-template-columns:1fr;

}}

.card {{

padding:18px;

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

<h1>
📝 سامانه غدیر
</h1>

<p style="text-align:center;color:#cbd5e1;">
سامانه ثبت و پیگیری گزارش
</p>

<form method="POST" action="/report">

<input
type="password"
name="report_password"
placeholder="رمز ثبت گزارش"
required
>

<textarea
name="report"
placeholder="گزارش خود را اینجا بنویسید..."
required
></textarea>

<button type="submit">
ثبت گزارش
</button>

</form>

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
# موفقیت
# =========================

def success_page(code):

    return page(
        "ثبت موفق",
        f"""

<div class="card">

<div class="success">

<h2>
✅ گزارش ثبت شد
</h2>

<p>
گزارش شما با موفقیت ذخیره شد.
</p>

<div class="code">

کد پیگیری:

<br>

{html.escape(code)}

</div>

<p>
این کد را برای پیگیری نگه دارید.
</p>

</div>

<a class="back" href="/">
بازگشت به صفحه اصلی
</a>

</div>

"""
    )


# =========================
# خطا
# =========================

def error_page(error_text):

    return page(
        "خطا",
        f"""

<div class="card">

<div class="error">

<h2>
❌ عملیات ناموفق بود
</h2>

<p>
{html.escape(str(error_text))}
</p>

</div>

<a class="back" href="/">
بازگشت
</a>

</div>

"""
    )


# =========================
# ورود مدیریت
# =========================

def admin_login_page():

    return page(
        "ورود مدیریت",
        """

<div class="card">

<h1>
🔐 ورود مدیریت
</h1>

<form method="POST" action="/login">

<input
type="password"
name="password"
placeholder="رمز مدیریت"
required
>

<button type="submit">
ورود
</button>

</form>

<a class="back" href="/">
بازگشت
</a>

</div>

"""
    )


# =========================
# بررسی ورود
# =========================

def is_logged_in(handler):

    cookie = handler.headers.get(
        "Cookie",
        ""
    )

    return cookie == (
        "session=" + SESSION_TOKEN
    )


# =========================
# پنل مدیریت
# =========================

def reports_page(search=""):

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

            if search in str(
                item.get("report", "")
            ).lower()

            or search in str(
                item.get("tracking_code", "")
            ).lower()

            or search in str(
                item.get("status", "")
            ).lower()

        ]

    total = len(reports)

    new_count = sum(
        1
        for x in reports
        if x.get("status", "جدید") == "جدید"
    )

    checked_count = sum(
        1
        for x in reports
        if x.get("status", "") == "بررسی‌شده"
    )

    reports_html = ""

    for item in reports:

        report_id = str(
            item.get("id", "")
        )

        report_text = html.escape(
            str(item.get("report", ""))
        )

        created_at = html.escape(
            str(item.get("created_at", ""))
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

وضعیت:
{status}

</div>

<div class="code">

کد پیگیری:

{tracking_code}

</div>

<div class="report-text">

{report_text}

</div>

<div class="date">

زمان ثبت:

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

<div class="card">

هنوز گزارشی پیدا نشد.

</div>

"""

    return page(
        "پنل مدیریت",
        f"""

<div class="card">

<h1>
📋 پنل مدیریت سامانه غدیر
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

<form
method="GET"
action="/reports"
>

<input
type="text"
name="search"
value="{html.escape(search)}"
placeholder="🔎 جست‌وجو..."
>

<button type="submit">
جست‌وجو
</button>

</form>

{reports_html}

<form
method="POST"
action="/logout"
>

<button
class="logout"
type="submit"
>

🚪 خروج

</button>

</form>

<a class="back" href="/">
بازگشت
</a>

</div>

"""
    )


# =========================
# پیگیری
# =========================

def track_page(message=""):

    message_html = ""

    if message:

        message_html = f"""

<div class="error">

{html.escape(message)}

</div>

"""

    return page(
        "پیگیری گزارش",
        f"""

<div class="card">

<h1>
🔎 پیگیری گزارش
</h1>

{message_html}

<form
method="GET"
action="/track"
>

<input
type="text"
name="code"
placeholder="مثلاً GHD-A1B2C3D4"
required
>

<button type="submit">
پیگیری
</button>

</form>

<a class="back" href="/">
بازگشت
</a>

</div>

"""
    )


# =========================
# نتیجه پیگیری
# =========================

def track_result(code):

    encoded_code = quote(
        code,
        safe=""
    )

    url = (
        SUPABASE_URL
        + "/rest/v1/reports"
        + "?select=created_at,status,tracking_code"
        + "&tracking_code=eq."
        + encoded_code
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

<h1>
📄 نتیجه پیگیری
</h1>

<div class="code">

{html.escape(code)}

</div>

<div class="badge">

وضعیت:
{status}

</div>

<p>

زمان ثبت:

{created}

</p>

<a class="back" href="/track">
پیگیری دوباره
</a>

<a class="back" href="/">
صفحه اصلی
</a>

</div>

"""
    )


# =========================
# سرور
# =========================

class Server(
    BaseHTTPRequestHandler
):

    def do_GET(self):

        parsed = urlparse(
            self.path
        )

        path = parsed.path

        query = parse_qs(
            parsed.query
        )

        if path == "/":

            self.send_html(
                main_page()
            )

            return

        if path == "/admin":

            self.send_html(
                admin_login_page()
            )

            return

        if path == "/reports":

            if not is_logged_in(self):

                self.send_response(403)

                self.end_headers()

                return

            try:

                search = query.get(
                    "search",
                    [""]
                )[0]

                self.send_html(
                    reports_page(search)
                )

            except Exception as e:

                self.send_html(
                    error_page(e)
                )

            return

        if path == "/track":

            code = query.get(
                "code",
                [""]
            )[0].strip()

            try:

                if code:

                    self.send_html(
                        track_result(code)
                    )

                else:

                    self.send_html(
                        track_page()
                    )

            except Exception as e:

                self.send_html(
                    error_page(e)
                )

            return

        self.send_response(404)

        self.end_headers()


    def do_POST(self):

        length = int(
            self.headers.get(
                "Content-Length",
                0
            )
        )

        data = self.rfile.read(
            length
        ).decode(
            "utf-8"
        )

        info = parse_qs(
            data
        )


        # =====================
        # ثبت گزارش
        # =====================

        if self.path == "/report":

            report_password = info.get(
                "report_password",
                [""]
            )[0]

            if not REPORT_PASSWORD:

                self.send_html(
                    error_page(
                        "REPORT_PASSWORD تنظیم نشده."
                    )
                )

                return

            if not hmac.compare_digest(
                report_password,
                REPORT_PASSWORD
            ):

                self.send_html(
                    error_page(
                        "رمز ثبت گزارش اشتباه است."
                    )
                )

                return

            report = info.get(
                "report",
                [""]
            )[0].strip()

            if not report:

                self.send_html(
                    error_page(
                        "متن گزارش خالی است."
                    )
                )

                return

            try:

                tracking_code = (
                    "GHD-"
                    + secrets.token_hex(
                        4
                    ).upper()
                )

                supabase_request(
                    "POST",
                    SUPABASE_URL
                    + "/rest/v1/reports",
                    {
                        "report": report,
                        "tracking_code":
                            tracking_code,
                        "status":
                            "جدید"
                    }
                )

                self.send_html(
                    success_page(
                        tracking_code
                    )
                )

            except Exception as e:

                print(
                    "REPORT ERROR:",
                    repr(e)
                )

                self.send_html(
                    error_page(e)
                )

            return


        # =====================
        # ورود
        # =====================

        if self.path == "/login":

            password = info.get(
                "password",
                [""]
            )[0]

            if hmac.compare_digest(
                password,
                ADMIN_PASSWORD
            ):

                self.send_response(302)

                self.send_header(
                    "Location",
                    "/reports"
                )

                self.send_header(
                    "Set-Cookie",
                    "session="
                    + SESSION_TOKEN
                    + "; HttpOnly; Secure; SameSite=Strict"
                )

                self.end_headers()

            else:

                self.send_html(
                    error_page(
                        "رمز مدیریت اشتباه است."
                    )
                )

            return


        # =====================
        # تغییر وضعیت
        # =====================

        if self.path == "/status":

            if not is_logged_in(self):

                self.send_response(403)

                self.end_headers()

                return

            report_id = info.get(
                "id",
                [""]
            )[0]

            status = info.get(
                "status",
                ["جدید"]
            )[0]

            allowed = [
                "جدید",
                "در حال بررسی",
                "بررسی‌شده"
            ]

            if (
                not report_id.isdigit()
                or status not in allowed
            ):

                self.send_html(
                    error_page(
                        "اطلاعات نامعتبر است."
                    )
                )

                return

            try:

                supabase_request(
                    "PATCH",
                    SUPABASE_URL
                    + "/rest/v1/reports"
                    + "?id=eq."
                    + report_id,
                    {
                        "status": status
                    }
                )

                self.send_response(302)

                self.send_header(
                    "Location",
                    "/reports"
                )

                self.end_headers()

            except Exception as e:

                self.send_html(
                    error_page(e)
                )

            return


        # =====================
        # حذف
        # =====================

        if self.path == "/delete":

            if not is_logged_in(self):

                self.send_response(403)

                self.end_headers()

                return

            report_id = info.get(
                "id",
                [""]
            )[0]

            if not report_id.isdigit():

                self.send_html(
                    error_page(
                        "شناسه نامعتبر است."
                    )
                )

                return

            try:

                supabase_request(
                    "DELETE",
                    SUPABASE_URL
                    + "/rest/v1/reports"
                    + "?id=eq."
                    + report_id
                )

                self.send_response(302)

                self.send_header(
                    "Location",
                    "/reports"
                )

                self.end_headers()

            except Exception as e:

                self.send_html(
                    error_page(e)
                )

            return


        # =====================
        # خروج
        # =====================

        if self.path == "/logout":

            self.send_response(302)

            self.send_header(
                "Location",
                "/"
            )

            self.send_header(
                "Set-Cookie",
                "session=deleted; "
                "HttpOnly; "
                "Secure; "
                "SameSite=Strict; "
                "Max-Age=0"
            )

            self.end_headers()

            return

        self.send_response(404)

        self.end_headers()


    def send_html(self, content):

        self.send_response(200)

        self.send_header(
            "Content-Type",
            "text/html; charset=utf-8"
        )

        self.end_headers()

        self.wfile.write(
            content.encode("utf-8")
   
