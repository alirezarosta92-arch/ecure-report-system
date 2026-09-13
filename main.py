from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs
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

SESSION_TOKEN = secrets.token_urlsafe(32)


# =========================
# ارتباط با Supabase
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

            text = response.read().decode(
                "utf-8"
            )

            print(
                "SUPABASE STATUS:",
                response.status
            )

            print(
                "SUPABASE RESPONSE:",
                text
            )

            if text:
                return json.loads(text)

            return None

    except urllib.error.HTTPError as e:

        error_body = e.read().decode(
            "utf-8",
            errors="replace"
        )

        print(
            "SUPABASE HTTP ERROR:",
            e.code
        )

        print(
            "SUPABASE ERROR BODY:",
            error_body
        )

        raise Exception(
            f"Supabase HTTP {e.code}: {error_body}"
        )

    except Exception as e:

        print(
            "SUPABASE ERROR:",
            repr(e)
        )

        raise


# =========================
# HTML اصلی
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
    box-sizing: border-box;
}}

body {{
    margin: 0;
    font-family: Tahoma, Arial, sans-serif;
    background: #0f172a;
    color: white;
}}

.container {{
    width: 92%;
    max-width: 850px;
    margin: 40px auto;
}}

.card {{
    background: #1e293b;
    border-radius: 20px;
    padding: 25px;
    box-shadow: 0 10px 30px rgba(0,0,0,.25);
}}

h1 {{
    text-align: center;
    margin-bottom: 25px;
}}

textarea {{
    width: 100%;
    min-height: 180px;
    resize: vertical;
    border: none;
    outline: none;
    border-radius: 15px;
    padding: 15px;
    font-size: 16px;
    font-family: Tahoma, Arial, sans-serif;
    background: #334155;
    color: white;
    margin-top: 10px;
}}

input[type="password"] {{
    width: 100%;
    padding: 15px;
    border-radius: 12px;
    border: none;
    outline: none;
    background: #334155;
    color: white;
    font-size: 16px;
    margin-bottom: 10px;
}}

button {{
    width: 100%;
    border: none;
    border-radius: 12px;
    padding: 14px;
    margin-top: 15px;
    font-size: 16px;
    cursor: pointer;
    background: #2563eb;
    color: white;
}}

button:hover {{
    background: #1d4ed8;
}}

.delete {{
    background: #dc2626;
}}

.delete:hover {{
    background: #b91c1c;
}}

.success {{
    background: #166534;
    padding: 18px;
    border-radius: 12px;
    text-align: center;
}}

.error {{
    background: #991b1b;
    padding: 18px;
    border-radius: 12px;
    text-align: center;
    word-break: break-word;
}}

.report {{
    background: #334155;
    border-radius: 15px;
    padding: 18px;
    margin-bottom: 15px;
}}

.report-text {{
    white-space: pre-wrap;
    line-height: 1.8;
    margin-bottom: 10px;
}}

.date {{
    color: #cbd5e1;
    font-size: 13px;
}}

.back {{
    display: block;
    text-align: center;
    color: #93c5fd;
    margin-top: 20px;
    text-decoration: none;
}}

.empty {{
    text-align: center;
    color: #cbd5e1;
    padding: 30px;
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

    content = """

<div class="card">

<h1>📝 سامانه غدیر</h1>

<form method="POST" action="/report">

<input
type="password"
name="report_password"
placeholder="رمز ثبت گزارش"
required>

<textarea
name="report"
placeholder="گزارش خود را اینجا بنویسید..."
required></textarea>

<button type="submit">
ثبت گزارش
</button>

</form>

<a class="back" href="/admin">
ورود به پنل مدیریت
</a>

</div>

"""

    return page(
        "سامانه غدیر",
        content
    )


# =========================
# صفحه موفقیت
# =========================

def success_page():

    content = """

<div class="card">

<div class="success">

<h2>✅ گزارش با موفقیت ثبت شد</h2>

<p>
گزارش شما ذخیره شد.
</p>

</div>

<a class="back" href="/">
بازگشت به صفحه اصلی
</a>

</div>

"""

    return page(
        "ثبت موفق",
        content
    )


# =========================
# صفحه خطا
# =========================

def error_page(error_text):

    safe_error = html.escape(
        str(error_text)
    )

    content = f"""

<div class="card">

<div class="error">

<h2>❌ عملیات ناموفق بود</h2>

<p>{safe_error}</p>

</div>

<a class="back" href="/">
بازگشت به صفحه اصلی
</a>

</div>

"""

    return page(
        "خطا",
        content
    )


# =========================
# صفحه ورود مدیریت
# =========================

def admin_login_page():

    content = """

<div class="card">

<h1>🔐 ورود مدیریت</h1>

<form method="POST" action="/login">

<input
type="password"
name="password"
placeholder="رمز مدیریت"
required>

<button type="submit">
ورود
</button>

</form>

<a class="back" href="/">
بازگشت
</a>

</div>

"""

    return page(
        "ورود مدیریت",
        content
    )


# =========================
# صفحه گزارش‌ها
# =========================

def reports_page():

    try:

        url = (
            SUPABASE_URL
            + "/rest/v1/reports"
            + "?select=id,created_at,report"
            + "&order=created_at.desc"
        )

        reports = supabase_request(
            "GET",
            url
        )

        if not reports:

            reports_html = """

<div class="empty">

هنوز گزارشی ثبت نشده است.

</div>

"""

        else:

            reports_html = ""

            for item in reports:

                report_id = str(
                    item.get("id", "")
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

                reports_html += f"""

<div class="report">

<div class="report-text">
{report_text}
</div>

<div class="date">
زمان ثبت: {created_at}
</div>

<form
method="POST"
action="/delete">

<input
type="hidden"
name="id"
value="{html.escape(report_id)}">

<button
class="delete"
type="submit"
onclick="return confirm('آیا از حذف این گزارش مطمئن هستید؟');">

🗑️ حذف گزارش

</button>

</form>

</div>

"""

        content = f"""

<div class="card">

<h1>📋 گزارش‌های ثبت‌شده</h1>

{reports_html}

<a class="back" href="/">
بازگشت به صفحه اصلی
</a>

</div>

"""

        return page(
            "گزارش‌های سامانه غدیر",
            content
        )

    except Exception as e:

        return error_page(e)


# =========================
# سرور
# =========================

class Server(BaseHTTPRequestHandler):

    def do_HEAD(self):

        if self.path == "/":

            self.send_response(200)

            self.send_header(
                "Content-Type",
                "text/html; charset=utf-8"
            )

            self.end_headers()

            return

        self.send_response(404)
        self.end_headers()


    # =====================
    # GET
    # =====================

    def do_GET(self):

        if self.path == "/":

            self.send_html(
                main_page()
            )

            return


        if self.path == "/admin":

            self.send_html(
                admin_login_page()
            )

            return


        if self.path == "/reports":

            cookie = self.headers.get(
                "Cookie",
                ""
            )

            if cookie == (
                "session="
                + SESSION_TOKEN
            ):

                self.send_html(
                    reports_page()
                )

            else:

                self.send_response(403)

                self.send_header(
                    "Content-Type",
                    "text/html; charset=utf-8"
                )

                self.end_headers()

                self.wfile.write(
                    "دسترسی غیرمجاز".encode(
                        "utf-8"
                    )
                )

            return


        self.send_response(404)
        self.end_headers()


    # =====================
    # POST
    # =====================

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

        info = parse_qs(data)


        # =================
        # ثبت گزارش
        # =================

        if self.path == "/report":

            report_password = info.get(
                "report_password",
                [""]
            )[0]

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

                url = (
                    SUPABASE_URL
                    + "/rest/v1/reports"
                )

                print(
                    "SENDING REPORT TO:",
                    url
                )

                supabase_request(
                    "POST",
                    url,
                    {
                        "report": report
                    }
                )

                self.send_html(
                    success_page()
                )

            except Exception as e:

                print(
                    "REPORT SAVE ERROR:",
                    repr(e)
                )

                self.send_html(
                    error_page(e)
                )

            return


        # =================
        # ورود مدیریت
        # =================

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


        # =================
        # حذف گزارش
        # =================

        if self.path == "/delete":

            cookie = self.headers.get(
                "Cookie",
                ""
            )


            if cookie != (
                "session="
                + SESSION_TOKEN
            ):

                self.send_response(403)

                self.send_header(
                    "Content-Type",
                    "text/html; charset=utf-8"
                )

                self.end_headers()

                self.wfile.write(
                    "دسترسی غیرمجاز".encode(
                        "utf-8"
                    )
                )

                return


            report_id = info.get(
                "id",
                [""]
            )[0]


            if not report_id.isdigit():

                self.send_html(
                    error_page(
                        "شناسه گزارش نامعتبر است."
                    )
                )

                return


            try:

                url = (
                    SUPABASE_URL
                    + "/rest/v1/reports"
                    + "?id=eq."
                    + report_id
                )

                print(
                    "DELETING REPORT:",
                    report_id
                )

                supabase_request(
                    "DELETE",
                    url
                )

                self.send_response(302)

                self.send_header(
                    "Location",
                    "/reports"
                )

                self.end_headers()

            except Exception as e:

                print(
                    "DELETE ERROR:",
                    repr(e)
                )

                self.send_html(
                    error_page(e)
                )

            return


        self.send_response(404)
        self.end_headers()


    # =====================
    # ارسال HTML
    # =====================

    def send_html(self, content):

        self.send_response(200)

        self.send_header(
            "Content-Type",
            "text/html; charset=utf-8"
        )

        self.end_headers()

        self.wfile.write(
            content.encode(
                "utf-8"
            )
        )


# =========================
# اجرای برنامه
# =========================

PORT = int(
    os.environ.get(
        "PORT",
        8080
    )
)

print(
    "================================"
)

print(
    "سامانه غدیر اجرا شد"
)

print(
    "SUPABASE_URL:",
    SUPABASE_URL
)

print(
    "SUPABASE_SECRET_KEY موجود:",
    bool(
        SUPABASE_SECRET_KEY
    )
)

print(
    "ADMIN_PASSWORD موجود:",
    bool(
        ADMIN_PASSWORD
    )
)

print(
    "REPORT_PASSWORD موجود:",
    bool(
        REPORT_PASSWORD
    )
)

print(
    "================================"
)


server = HTTPServer(
    ("0.0.0.0", PORT),
    Server
)

server.serve_forever()
