import os
import json
import time
import secrets
import hmac
import urllib.request
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(os.getenv("PORT", "10000"))

SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_KEY = os.getenv("SUPABASE_SECRET_KEY", "")

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
REPORT_PASSWORD = os.getenv("REPORT_PASSWORD", "")

sessions = {}
login_attempts = {}

MAX_REPORT_LENGTH = 10000
SESSION_TIME = 2 * 60 * 60


def supabase_request(method, path, data=None):
    url = SUPABASE_URL + path

    headers = {
        "apikey": SUPABASE_KEY,
        "Authorization": "Bearer " + SUPABASE_KEY,
        "Content-Type": "application/json",
        "Accept": "application/json",
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
            raw = response.read().decode("utf-8")
            if not raw:
                return None
            return json.loads(raw)
    except Exception as e:
        print("Supabase error:", e)
        return None


def create_session():
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(24)

    sessions[token] = {
        "created": time.time(),
        "csrf": csrf
    }

    return token, csrf


def get_session(handler):
    cookie = handler.headers.get("Cookie", "")

    for item in cookie.split(";"):
        item = item.strip()

        if item.startswith("session="):
            token = item.split("=", 1)[1]

            session = sessions.get(token)

            if session:
                if time.time() - session["created"] < SESSION_TIME:
                    return token, session

                del sessions[token]

    return None, None


def escape(text):
    text = str(text)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#039;")
    )


def page(title, content):
    return """<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<title>سامانه غدیر</title>

<style>

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    font-family: Tahoma, Arial, sans-serif;
    background:
        radial-gradient(circle at top right, #263c66, transparent 40%),
        radial-gradient(circle at bottom left, #17233d, transparent 45%),
        #070b14;
    color: white;
    min-height: 100vh;
}

.container {
    width: min(900px, 92%);
    margin: 40px auto;
}

.header {
    text-align: center;
    margin-bottom: 25px;
}

.header h1 {
    font-size: 36px;
    margin: 0 0 10px;
}

.header p {
    color: #aeb8cc;
}

.card {
    background: rgba(20, 29, 48, 0.82);
    border: 1px solid rgba(255,255,255,0.09);
    border-radius: 22px;
    padding: 25px;
    margin-bottom: 20px;
    box-shadow: 0 15px 50px rgba(0,0,0,.35);
    backdrop-filter: blur(12px);
}

.center {
    text-align: center;
}

label {
    display: block;
    margin-bottom: 8px;
    color: #dce4f5;
}

input,
textarea,
select {
    width: 100%;
    border: 1px solid #35425e;
    background: #0d1423;
    color: white;
    border-radius: 13px;
    padding: 14px;
    outline: none;
    font-size: 15px;
    margin-bottom: 15px;
}

textarea {
    min-height: 180px;
    resize: vertical;
}

input:focus,
textarea:focus,
select:focus {
    border-color: #6e8edb;
}

button,
.btn {
    display: inline-block;
    border: 0;
    border-radius: 13px;
    padding: 13px 20px;
    cursor: pointer;
    background: #4169e1;
    color: white;
    font-size: 15px;
    text-decoration: none;
    margin: 4px;
}

button:hover,
.btn:hover {
    opacity: .88;
}

.danger {
    background: #a83232;
}

.success {
    background: rgba(40,160,90,.15);
    border: 1px solid rgba(80,220,130,.3);
    padding: 15px;
    border-radius: 13px;
    margin-bottom: 15px;
}

.error {
    background: rgba(180,40,40,.15);
    border: 1px solid rgba(255,80,80,.3);
    padding: 15px;
    border-radius: 13px;
    margin-bottom: 15px;
}

.code {
    font-size: 24px;
    font-weight: bold;
    letter-spacing: 2px;
    direction: ltr;
    margin: 15px 0;
}

.report {
    white-space: pre-wrap;
    line-height: 1.9;
    background: #0b111e;
    padding: 18px;
    border-radius: 14px;
    margin-top: 15px;
}

.small {
    color: #8f9bb0;
    font-size: 13px;
}

a {
    color: #9db6ff;
}

</style>
</head>

<body>

<div class="container">

<div class="header">
<h1>🛡️ سامانه غدیر</h1>
<p>سامانه ثبت و پیگیری گزارش</p>
</div>

""" + content + """

</div>

</body>
</html>
"""


def send_html(handler, html, status=200, extra_headers=None):
    data = html.encode("utf-8")

    handler.send_response(status)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(data)))

    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("X-Frame-Options", "DENY")
    handler.send_header("Referrer-Policy", "no-referrer")
    handler.send_header("Cache-Control", "no-store")

    if extra_headers:
        for key, value in extra_headers.items():
            handler.send_header(key, value)

    handler.end_headers()
    handler.wfile.write(data)


def home():
    return page(
        "صفحه اصلی",
        """
<div class="card">

<h2>ثبت گزارش</h2>

<p>
اگر می‌خواهید گزارشی ثبت کنید، از گزینه زیر استفاده کنید.
</p>

<a class="btn" href="/report">ثبت گزارش</a>
<a class="btn" href="/track">پیگیری گزارش</a>
<a class="btn" href="/admin">مدیریت سامانه</a>

</div>
"""
    )


def report_page(error=""):
    error_html = ""

    if error:
        error_html = '<div class="error">' + escape(error) + "</div>"

    return page(
        "ثبت گزارش",
        """
<div class="card">

<h2>📝 ثبت گزارش</h2>

""" + error_html + """

<form method="POST" action="/submit">

<label>گزارش</label>

<textarea
name="report"
maxlength="10000"
required
placeholder="متن گزارش خود را وارد کنید..."
></textarea>

<label>رمز ثبت گزارش</label>

<input
type="password"
name="password"
required
placeholder="رمز ثبت گزارش"
/>

<button type="submit">ثبت گزارش</button>

</form>

<a class="btn" href="/">بازگشت</a>

</div>
"""
    )


def track_page():
    return page(
        "پیگیری",
        """
<div class="card">

<h2>🔎 پیگیری گزارش</h2>

<form method="GET" action="/track">

<label>کد پیگیری</label>

<input
name="code"
placeholder="مثلاً GHD-ABC1234567"
required
/>

<button type="submit">پیگیری</button>

</form>

<a class="btn" href="/">بازگشت</a>

</div>
"""
    )


def admin_page(error=""):
    error_html = ""

    if error:
        error_html = '<div class="error">' + escape(error) + "</div>"

    return page(
        "ورود مدیریت",
        """
<div class="card">

<h2>🔐 مدیریت سامانه</h2>

""" + error_html + """

<form method="POST" action="/login">

<label>رمز مدیریت</label>

<input
type="password"
name="password"
required
/>

<button type="submit">ورود</button>

</form>

<a class="btn" href="/">بازگشت</a>

</div>
"""
    )


def reports_page(handler):
    token, session = get_session(handler)

    if not session:
        return admin_page("ابتدا وارد بخش مدیریت شوید.")

    reports = supabase_request(
        "GET",
        "/rest/v1/reports?select=*&order=id.desc"
    )

    if reports is None:
        return page(
            "خطا",
            """
<div class="card">
<div class="error">
خطا در دریافت گزارش‌ها از پایگاه داده.
</div>
<a class="btn" href="/admin">بازگشت</a>
</div>
"""
        )

    cards = ""

    csrf = session["csrf"]

    if not reports:
        cards = """
<div class="card center">
<p>هنوز گزارشی ثبت نشده است.</p>
</div>
"""
    else:
        for report in reports:
            rid = escape(report.get("id", ""))
            text = escape(report.get("report", ""))
            code = escape(report.get("tracking_code", ""))
            status = escape(report.get("status", "جدید"))
            created = escape(report.get("created_at", ""))

            cards += """
<div class="card">

<h3>گزارش #""" + rid + """</h3>

<p class="small">
کد پیگیری: """ + code + """
</p>

<p class="small">
وضعیت: """ + status + """
</p>

<p class="small">
تاریخ ثبت: """ + created + """
</p>

<div class="report">""" + text + """</div>

<form method="POST" action="/status">

<input type="hidden" name="csrf" value=\"""" + csrf + """\">
<input type="hidden" name="id" value=\"""" + rid + """\">

<select name="status">
<option value="جدید">جدید</option>
<option value="در حال بررسی">در حال بررسی</option>
<option value="بررسی شد">بررسی شد</option>
<option value="بسته شد">بسته شد</option>
</select>

<button type="submit">تغییر وضعیت</button>

</form>

<form method="POST" action="/delete"
onsubmit="return confirm('آیا از حذف این گزارش مطمئن هستید؟');">

<input type="hidden" name="csrf" value=\"""" + csrf + """\">
<input type="hidden" name="id" value=\"""" + rid + """\">

<button class="danger" type="submit">
حذف گزارش
</button>

</form>

</div>
"""

    return page(
        "گزارش‌ها",
        cards + """
<div class="card center">
<a class="btn" href="/logout">خروج از مدیریت</a>
</div>
"""
    )


def find_report(code):
    code = urllib.parse.quote(code, safe="")

    result = supabase_request(
        "GET",
        "/rest/v1/reports?tracking_code=eq." + code + "&select=*"
    )

    if result and isinstance(result, list):
        return result[0]

    return None


def track_result(code):
    report = find_report(code)

    if not report:
        return page(
            "پیگیری",
            """
<div class="card">

<div class="error">
گزارشی با این کد پیگیری پیدا نشد.
</div>

<a class="btn" href="/track">تلاش دوباره</a>

</div>
"""
        )

    text = escape(report.get("report", ""))
    status = escape(report.get("status", "جدید"))
    tracking = escape(report.get("tracking_code", ""))

    return page(
        "نتیجه پیگیری",
        """
<div class="card">

<h2>📄 نتیجه پیگیری</h2>

<p>
کد پیگیری:
</p>

<div class="code">""" + tracking + """</div>

<p>
وضعیت:
<strong>""" + status + """</strong>
</p>

<div class="report">
""" + text + """
</div>

<a class="btn" href="/track">بازگشت</a>

</div>
"""
    )


class Handler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        print(format % args)

    def read_post(self):
        length = int(self.headers.get("Content-Length", "0"))

        if length > 15000:
            return {}

        body = self.rfile.read(length).decode("utf-8", errors="replace")

        return urllib.parse.parse_qs(
            body,
            keep_blank_values=True
        )

    def redirect(self, location):
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def do_GET(self):

        path = urllib.parse.urlparse(self.path).path

        if path == "/":
            send_html(self, home())
            return

        if path == "/report":
            send_html(self, report_page())
            return

        if path == "/track":
            query = urllib.parse.parse_qs(
                urllib.parse.urlparse(self.path).query
            )

            code = query.get("code", [""])[0].strip()

            if code:
                send_html(self, track_result(code))
            else:
                send_html(self, track_page())

            return

        if path == "/admin":

            token, session = get_session(self)

            if session:
                send_html(self, reports_page(self))
            else:
                send_html(self, admin_page())

            return

        if path == "/logout":

            token, session = get_session(self)

            if token:
                sessions.pop(token, None)

            self.send_response(303)
            self.send_header("Location", "/")
            self.send_header(
                "Set-Cookie",
                "session=deleted; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"
            )
            self.end_headers()

            return

        send_html(
            self,
            page(
                "404",
                """
<div class="card center">
<h2>صفحه پیدا نشد</h2>
<a class="btn" href="/">صفحه اصلی</a>
</div>
"""
            ),
            404
        )

    def do_POST(self):

        path = urllib.parse.urlparse(self.path).path
        form = self.read_post()

        if path == "/submit":

            password = form.get("password", [""])[0]
            report = form.get("report", [""])[0].strip()

            if not hmac.compare_digest(
                password,
                REPORT_PASSWORD
            ):
                send_html(
                    self,
                    report_page("رمز ثبت گزارش اشتباه است."),
                    403
                )
                return

            if not report:
                send_html(
                    self,
                    report_page("متن گزارش خالی است."),
                    400
                )
                return

            if len(report) > MAX_REPORT_LENGTH:
                send_html(
                    self,
                    report_page("گزارش بیش از حد طولانی است."),
                    400
                )
                return

            tracking_code = (
                "GHD-" +
                secrets.token_hex(5).upper()
            )

            result = supabase_request(
                "POST",
                "/rest/v1/reports",
                {
                    "report": report,
                    "tracking_code": tracking_code,
                    "status": "جدید"
                }
            )

            if result is None:
                send_html(
                    self,
                    report_page(
                        "ثبت گزارش انجام نشد. دوباره تلاش کنید."
                    ),
                    500
                )
                return

            send_html(
                self,
                page(
                    "گزارش ثبت شد",
                    """
<div class="card center">

<h2>✅ گزارش با موفقیت ثبت شد</h2>

<p>
کد پیگیری شما:
</p>

<div class="code">
""" + escape(tracking_code) + """
</div>

<p class="small">
این کد را برای پیگیری گزارش نزد خود نگه دارید.
</p>

<a class="btn" href="/track">
پیگیری گزارش
</a>

<a class="btn" href="/">
صفحه اصلی
</a>

</div>
"""
                )
            )

            return

        if path == "/login":

            password = form.get("password", [""])[0]

            now = time.time()
            ip = self.client_address[0]

            attempts = login_attempts.get(ip, [])

            attempts = [
                t for t in attempts
                if now - t < 600
            ]

            if len(attempts) >= 5:
                send_html(
                    self,
                    admin_page(
                        "تعداد تلاش‌ها زیاد است. چند دقیقه بعد دوباره تلاش کنید."
                    ),
                    429
                )
                return

            attempts.append(now)
            login_attempts[ip] = attempts

            if not hmac.compare_digest(
                password,
                ADMIN_PASSWORD
            ):
                send_html(
                    self,
                    admin_page("رمز مدیریت اشتباه است."),
                    403
                )
                return

            token, csrf = create_session()

            self.send_response(303)
            self.send_header("Location", "/admin")
            self.send_header(
                "Set-Cookie",
                "session=" + token +
                "; Path=/; HttpOnly; SameSite=Lax; Secure"
            )
            self.send_header("Cache-Control", "no-store")
            self.end_headers()

            return

        if path == "/status":

            token, session = get_session(self)

            if not session:
                send_html(
                    self,
                    admin_page("نشست مدیریت منقضی شده است."),
                    403
                )
                return

            csrf = form.get("csrf", [""])[0]

            if not hmac.compare_digest(
                csrf,
                session["csrf"]
            ):
                send_html(
                    self,
                    admin_page("درخواست نامعتبر است."),
                    403
                )
                return

            rid = form.get("id", [""])[0]
            status = form.get("status", ["جدید"])[0]

            allowed = {
                "جدید",
                "در حال بررسی",
                "بررسی شد",
                "بسته شد"
            }

            if status not in allowed:
                status = "جدید"

            rid = urllib.parse.quote(rid, safe="")

            supabase_request(
                "PATCH",
                "/rest/v1/reports?id=eq." + rid,
                {
                    "status": status
                }
            )

            self.redirect("/admin")
            return

        if path == "/delete":

            token, session = get_session(self)

            if not session:
                send_html(
                    self,
                    admin_page("نشست مدیریت منقضی شده است."),
                    403
                )
                return

            csrf = form.get("csrf", [""])[0]

            if not hmac.compare_digest(
                csrf,
                session["csrf"]
            ):
                send_html(
                    self,
                    admin_page("درخواست نامعتبر است."),
                    403
                )
                return

            rid = form.get("id", [""])[0]
            rid = urllib.parse.quote(rid, safe="")

            supabase_request(
                "DELETE",
                "/rest/v1/reports?id=eq." + rid
            )

            self.redirect("/admin")
            return

        send_html(
            self,
            page(
                "404",
                """
<div class="card center">
<h2>درخواست نامعتبر</h2>
<a class="btn" href="/">صفحه اصلی</a>
</div>
"""
            ),
            404
        )


def cleanup_sessions():

    now = time.time()

    expired = []

    for token, session in sessions.items():

        if now - session["created"] > SESSION_TIME:
            expired.append(token)

    for token in expired:
        sessions.pop(token, None)


def main():

    if not SUPABASE_URL:
        print("ERROR: SUPABASE_URL is not set")

    if not SUPABASE_KEY:
        print("ERROR: SUPABASE_SECRET_KEY is not set")

    if not ADMIN_PASSWORD:
        print("WARNING: ADMIN_PASSWORD is not set")

    if not REPORT_PASSWORD:
        print("WARNING: REPORT_PASSWORD is not set")

    server = HTTPServer(
        ("0.0.0.0", PORT),
        Handler
    )

    print("================================")
    print("سامانه غدیر started")
    print("Port:", PORT)
    print("================================")

    while True:

        cleanup_sessions()

        server.handle_request()


if __name__ == "__main__":
    main()
