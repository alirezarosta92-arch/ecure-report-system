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
SUPABASE_URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
SUPABASE_SECRET_KEY = os.environ.get("SUPABASE_SECRET_KEY", "")
PORT = int(os.environ.get("PORT", 8080))

SESSION_TTL = 3600
SESSIONS = {}
LOGIN_ATTEMPTS = {}


# =========================
# SECURITY
# =========================

def cookies(handler):
    result = {}
    for part in handler.headers.get("Cookie", "").split(";"):
        if "=" in part:
            k, v = part.strip().split("=", 1)
            result[k] = v
    return result


def session(handler):
    token = cookies(handler).get("session")
    data = SESSIONS.get(token)

    if not data:
        return None

    if data["expires"] < time.time():
        SESSIONS.pop(token, None)
        return None

    return data


def new_session():
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)

    SESSIONS[token] = {
        "csrf": csrf,
        "expires": time.time() + SESSION_TTL
    }

    return token, csrf


def cookie(name, value, age=SESSION_TTL, http_only=True):
    text = f"{name}={value}; Path=/; SameSite=Strict; Secure; Max-Age={age}"

    if http_only:
        text += "; HttpOnly"

    return text


def csrf_ok(handler, form):
    s = session(handler)

    if not s:
        return False

    submitted = form.get("csrf", [""])[0]
    stored = s["csrf"]
    browser = cookies(handler).get("csrf", "")

    return (
        submitted
        and browser
        and hmac.compare_digest(submitted, stored)
        and hmac.compare_digest(browser, stored)
    )


# =========================
# SUPABASE
# =========================

def supabase(method, endpoint, data=None):
    headers = {
        "apikey": SUPABASE_SECRET_KEY,
        "Authorization": "Bearer " + SUPABASE_SECRET_KEY,
        "Content-Type": "application/json",
        "Prefer": "return=minimal"
    }

    body = None

    if data is not None:
        body = json.dumps(data).encode()

    req = urllib.request.Request(
        SUPABASE_URL + endpoint,
        data=body,
        headers=headers,
        method=method
    )

    with urllib.request.urlopen(req, timeout=15) as response:
        text = response.read().decode()

        return json.loads(text) if text else None


# =========================
# HTML
# =========================

CSS = """
<style>
*{box-sizing:border-box}

body{
margin:0;
font-family:Tahoma,Arial,sans-serif;
direction:rtl;
color:white;
min-height:100vh;
background:
radial-gradient(circle at 15% 20%,#1d4ed855,transparent 30%),
radial-gradient(circle at 85% 80%,#7c3aed55,transparent 30%),
linear-gradient(135deg,#020617,#0f172a);
}

.container{
width:92%;
max-width:900px;
margin:45px auto;
}

.card{
background:#0f172ae8;
border:1px solid #ffffff15;
border-radius:28px;
padding:30px;
box-shadow:0 25px 70px #0008;
backdrop-filter:blur(15px);
margin-bottom:20px;
}

.logo{
width:82px;
height:82px;
border-radius:25px;
margin:auto;
display:flex;
align-items:center;
justify-content:center;
font-size:40px;
background:linear-gradient(135deg,#2563eb,#7c3aed);
box-shadow:0 15px 40px #2563eb55;
}

h1{
text-align:center;
margin:18px 0 8px;
}

.subtitle{
text-align:center;
color:#94a3b8;
line-height:2;
margin-bottom:25px;
}

input,textarea,select{
width:100%;
padding:15px;
margin:7px 0;
border-radius:15px;
border:1px solid #ffffff12;
background:#1e293bcc;
color:white;
font-size:16px;
outline:none;
font-family:Tahoma,Arial;
}

textarea{
min-height:170px;
resize:vertical;
}

button{
width:100%;
padding:15px;
margin-top:10px;
border:0;
border-radius:15px;
color:white;
font-size:16px;
font-weight:bold;
cursor:pointer;
background:linear-gradient(135deg,#2563eb,#4f46e5);
}

button:hover{
filter:brightness(1.1);
}

.danger{
background:linear-gradient(135deg,#dc2626,#991b1b);
}

.green{
background:linear-gradient(135deg,#059669,#047857);
}

.gray{
background:linear-gradient(135deg,#475569,#334155);
}

a{
display:block;
text-align:center;
color:#93c5fd;
text-decoration:none;
margin-top:18px;
}

.success,.error{
padding:20px;
border-radius:18px;
text-align:center;
margin-bottom:20px;
}

.success{
background:#166534aa;
}

.error{
background:#991b1baa;
}

.report{
padding:20px;
border-radius:20px;
background:#1e293bcc;
margin:15px 0;
border:1px solid #ffffff10;
}

.code{
padding:14px;
margin:12px 0;
border-radius:14px;
background:#020617;
text-align:center;
color:#bfdbfe;
font-weight:bold;
}

.stats{
display:grid;
grid-template-columns:repeat(3,1fr);
gap:12px;
margin-bottom:20px;
}

.stat{
background:#1e293baa;
padding:18px;
border-radius:18px;
text-align:center;
}

.number{
font-size:28px;
font-weight:bold;
color:#bfdbfe;
}

@media(max-width:650px){
.container{margin:20px auto}
.card{padding:20px}
.stats{grid-template-columns:1fr}
}
</style>
"""


def page(title, body):
    return f"""
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title>
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
    error = f'<div class="error">{html.escape(message)}</div>' if message else ""

    return page(
        "ورود سامانه",
        f"""
<div class="card">

<div class="logo">🔐</div>

<h1>ورود به سامانه غدیر</h1>

<div class="subtitle">
برای ورود، نام کاربری و رمز عبور خود را وارد کنید.
</div>

{error}

<form method="POST" action="/login">

<input
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

<div class="logo">🛡️</div>

<h1>سامانه غدیر</h1>

<div class="subtitle">
سامانه ثبت و پیگیری گزارش‌ها
</div>

<a href="/report">
<button>📝 ثبت گزارش</button>
</a>

<a href="/track">
<button class="green">🔎 پیگیری گزارش</button>
</a>

<a href="/reports">
<button>📋 پنل مدیریت</button>
</a>

<form method="POST" action="/logout">
<button class="gray" type="submit">
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
    error = f'<div class="error">{html.escape(message)}</div>' if message else ""

    return page(
        "ثبت گزارش",
        f"""
<div class="card">

<div class="logo">📝</div>

<h1>ثبت گزارش</h1>

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
placeholder="✍️ گزارش خود را بنویسید..."
required
></textarea>

<button type="submit">
🚀 ثبت گزارش
</button>

</form>

<a href="/">🏠 بازگشت</a>

</div>
"""
    )


# =========================
# TRACK
# =========================

def track_page(message=""):
    error = f'<div class="error">{html.escape(message)}</div>' if message else ""

    return page(
        "پیگیری",
        f"""
<div class="card">

<div class="logo">🔎</div>

<h1>پیگیری گزارش</h1>

<div class="subtitle">
کد پیگیری را وارد کنید.
</div>

{error}

<form method="GET" action="/track">

<input
name="code"
placeholder="🎫 کد پیگیری"
required
>

<button type="submit">
🔎 پیگیری
</button>

</form>

<a href="/">🏠 بازگشت</a>

</div>
"""
    )


def track_result(code):
    endpoint = (
        "/rest/v1/reports"
        "?select=created_at,status,tracking_code"
        "&tracking_code=eq."
        + quote(code, safe="")
    )

    rows = supabase("GET", endpoint)

    if not rows:
        return track_page("گزارشی با این کد پیدا نشد.")

    item = rows[0]

    return page(
        "نتیجه پیگیری",
        f"""
<div class="card">

<div class="logo">📄</div>

<h1>نتیجه پیگیری</h1>

<div class="code">
🎫 {html.escape(str(item.get("tracking_code","")))}
</div>

<div class="success">
<h2>
وضعیت: {html.escape(str(item.get("status","جدید")))}
</h2>

زمان ثبت:
<br>
{html.escape(str(item.get("created_at","")))}
</div>

<a href="/track">🔎 پیگیری دوباره</a>
<a href="/">🏠 صفحه اصلی</a>

</div>
"""
    )


# =========================
# REPORTS
# =========================

def reports_page(search=""):
    endpoint = (
        "/rest/v1/reports"
        "?select=id,created_at,report,tracking_code,status"
        "&order=created_at.desc"
    )

    rows = supabase("GET", endpoint)

    search = search.strip().lower()

    if search:
        rows = [
            x for x in rows
            if search in str(x.get("report","")).lower()
            or search in str(x.get("tracking_code","")).lower()
            or search in str(x.get("status","")).lower()
        ]

    total = len(rows)
    new = sum(x.get("status","جدید") == "جدید" for x in rows)
    checked = sum(x.get("status","") == "بررسی‌شده" for x in rows)

    cards = ""

    for x in rows:
        rid = str(x.get("id",""))
        code = str(x.get("tracking_code",""))
        status = str(x.get("status","جدید"))

        cards += f"""
<div class="report">

<div class="code">
🎫 {html.escape(code)}
</div>

<p style="line-height:2">
{html.escape(str(x.get("report","")))}
</p>

<p style="color:#94a3b8">
🕐 {html.escape(str(x.get("created_at","")))}
</p>

<div class="success">
وضعیت فعلی: {html.escape(status)}
</div>

<form method="POST" action="/status">

<input type="hidden" name="id" value="{html.escape(rid)}">

<select name="status">
<option>جدید</option>
<option>در حال بررسی</option>
<option>بررسی‌شده</option>
</select>

<input
type="hidden"
name="csrf"
value="{html.escape(session_token)}"
>

<button class="green">
💾 تغییر وضعیت
</button>

</form>

<form method="POST" action="/delete">

<input type="hidden" name="id" value="{html.escape(rid)}">

<input
type="hidden"
name="csrf"
value="{html.escape(session_token)}"
>

<button class="danger">
🗑️ حذف گزارش
</button>

</form>

</div>
"""

    if not cards:
        cards = '<div class="error">گزارشی پیدا نشد.</div>'

    return page(
        "پنل مدیریت",
        f"""
<div class="card">

<div class="logo">📋</div>

<h1>پنل مدیریت</h1>

<div class="stats">

<div class="stat">
<div class="number">{total}</div>
کل گزارش‌ها
</div>

<div class="stat">
<div class="number">{new}</div>
گزارش جدید
</div>

<div class="stat">
<div class="number">{checked}</div>
بررسی‌شده
</div>

</div>

<form method="GET" action="/reports">

<input
name="search"
value="{html.escape(search)}"
placeholder="🔎 جست‌وجو..."
>

<button>
🔍 جست‌وجو
</button>

</form>

{cards}

<form method="POST" action="/logout">

<input
type="hidden"
name="csrf"
value="{html.escape(session_token)}"
>

<button class="gray">
🚪 خروج
</button>

</form>

<a href="/">🏠 صفحه اصلی</a>

</div>
"""
    )


# =========================
# SERVER
# =========================

session_token = ""


class Server(BaseHTTPRequestHandler):

    def send_html(self, text, status=200, extra=None):
        self.send_response(status)
        self.send_header(
            "Content-Type",
            "text/html; charset=utf-8"
        )
        self.send_header(
            "Cache-Control",
            "no-store"
        )

        if extra:
            for k, v in extra:
                self.send_header(k, v)

        self.end_headers()
        self.wfile.write(text.encode("utf-8"))

    def do_GET(self):

        global session_token

        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        try:

            if path == "/":
                if session(self):
                    self.send_html(home_page())
                else:
                    self.send_html(login_page())
                return

            if path == "/admin":
                if session(self):
                    self.send_html(home_page())
                else:
                    self.send_html(login_page())
                return

            if path == "/report":
                if not session(self):
                    self.send_html(login_page("ابتدا وارد حساب شوید."), 403)
                    return

                self.send_html(report_page())
                return

            if path == "/track":
                code = query.get("code", [""])[0].strip()

                if code:
                    self.send_html(track_result(code))
                else:
                    self.send_html(track_page())

                return

            if path == "/reports":
                s = session(self)

                if not s:
                    self.send_html(login_page("ابتدا وارد حساب شوید."), 403)
                    return

                session_token = s["csrf"]

                self.send_html(
                    reports_page(
                        query.get("search", [""])[0]
                    )
                )
                return

            self.send_html(
                page("404", '<div class="error">صفحه پیدا نشد.</div>'),
                404
            )

        except Exception as e:
            print("GET ERROR:", repr(e))
            self.send_html(
                page(
                    "خطا",
                    f'<div class="error">{html.escape(str(e))}</div>'
                ),
                500
            )

    def do_POST(self):

        global session_token

        length = int(
            self.headers.get("Content-Length", 0)
        )

        body = self.rfile.read(length).decode("utf-8")
        form = parse_qs(body)

        path = urlparse(self.path).path

        try:

            # LOGIN
            if path == "/login":

                username = form.get("username", [""])[0]
                password = form.get("password", [""])[0]

                if (
                    hmac.compare_digest(username, ADMIN_USERNAME)
                    and hmac.compare_digest(password, ADMIN_PASSWORD)
                ):

                    token, csrf = new_session()

                    self.send_response(302)
                    self.send_header("Location", "/")
                    self.send_header(
                        "Set-Cookie",
                        cookie("session", token)
                    )
                    self.send_header(
                        "Set-Cookie",
                        cookie("csrf", csrf, http_only=False)
                    )
                    self.end_headers()

                else:
                    self.send_html(
                        login_page("نام کاربری یا رمز عبور اشتباه است."),
                        403
                    )

                return

            # LOGOUT
            if path == "/logout":

                s = session(self)

                if not s or not csrf_ok(self, form):
                    self.send_html(
                        page(
                            "خطا",
                            '<div class="error">درخواست غیرمجاز است.</div>'
                        ),
                        403
                    )
                    return

                token = cookies(self).get("session")
                SESSIONS.pop(token, None)

                self.send_response(302)
                self.send_header("Location", "/")
                self.send_header(
                    "Set-Cookie",
                    cookie("session", "deleted", 0)
                )
                self.end_headers()
                return

            # SUBMIT REPORT
            if path == "/submit":

                if not session(self):
                    self.send_html(login_page(), 403)
                    return

                password = form.get(
                    "report_password",
                    [""]
                )[0]

                report = form.get(
                    "report",
                    [""]
                )[0].strip()

                if not hmac.compare_digest(
                    password,
                    REPORT_PASSWORD
                ):
                    self.send_html(
                        report_page("رمز ثبت گزارش اشتباه است."),
                        403
                    )
                    return

                if not report:
                    self.send_html(
                        report_page("متن گزارش خالی است."),
                        400
                    )
                    return

                code = (
                    "GHD-"
                    + secrets.token_hex(4).upper()
                )

                supabase(
                    "POST",
                    "/rest/v1/reports",
                    {
                        "report": report,
                        "tracking_code": code,
                        "status": "جدید"
                    }
                )

                self.send_html(
                    page(
                        "ثبت شد",
                        f"""
<div class="card">
<div class="success">
<h1>✅ گزارش ثبت شد</h1>
<p>کد پیگیری شما:</p>

<div class="code">
{html.escape(code)}
</div>

<p>این کد را نگه دارید.</p>
</div>

<a href="/">🏠 صفحه اصلی</a>
</div>
"""
                    )
                )
                return

            # STATUS
            if path == "/status":

                s = session(self)

                if not s or not csrf_ok(self, form):
                    self.send_html(
                        page(
                            "خطا",
                            '<div class="error">درخواست غیرمجاز است.</div>'
                        ),
                        403
                    )
                    return

                rid = form.get("id", [""])[0]
                status = form.get("status", [""])[0]

                allowed = {
                    "جدید",
                    "در حال بررسی",
                    "بررسی‌شده"
                }

                if not rid.isdigit() or status not in allowed:
                    self.send_html(
                        page(
                            "خطا",
                            '<div class="error">اطلاعات نامعتبر است.</div>'
                        ),
                        400
                    )
                    return

                supabase(
                    "PATCH",
                    "/rest/v1/reports?id=eq." + rid,
                    {"status": status}
                )

                self.send_response(302)
                self.send_header("Location", "/reports")
                self.end_headers()
                return

            # DELETE
            if path == "/delete":

                s = session(self)

                if not s or not csrf_ok(self, form):
                    self.send_html(
                        page(
                            "خطا",
                            '<div class="error">درخواست غیرمجاز است.</div>'
                        ),
                        403
                    )
                    return

                rid = form.get("id", [""])[0]

                if not rid.isdigit():
                    self.send_html(
                        page(
                            "خطا",
                            '<div class="error">شناسه نامعتبر است.</div>'
                        ),
                        400
                    )
                    return

                supabase(
                    "DELETE",
                    "/rest/v1/reports?id=eq." + rid
                )

                self.send_response(302)
                self.send_header("Location", "/reports")
     
