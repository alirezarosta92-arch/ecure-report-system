import os, json, time, secrets, hmac, urllib.request, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie

PORT = int(os.getenv("PORT", "10000"))
SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_KEY = os.getenv("SUPABASE_SECRET_KEY", "")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
REPORT_PASSWORD = os.getenv("REPORT_PASSWORD", "")

APP = "سامانه غدیر"
SESSIONS = {}
ATTEMPTS = {}
SESSION_TTL = 7200
MAX_REPORT = 10000


def compare(a, b):
    return hmac.compare_digest(str(a).encode(), str(b).encode())


def session(handler):
    c = SimpleCookie()
    c.load(handler.headers.get("Cookie", ""))
    if "session" not in c:
        return None

    sid = c["session"].value
    s = SESSIONS.get(sid)

    if not s:
        return None

    if time.time() - s["time"] > SESSION_TTL:
        del SESSIONS[sid]
        return None

    return s


def new_session():
    sid = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)

    SESSIONS[sid] = {
        "time": time.time(),
        "csrf": csrf,
        "admin": True
    }

    return sid


def db(method, path, data=None, params=None):
    url = SUPABASE_URL + path

    if params:
        url += "?" + urllib.parse.urlencode(params)

    body = None

    if data is not None:
        body = json.dumps(data).encode()

    req = urllib.request.Request(
        url,
        data=body,
        method=method
    )

    req.add_header("apikey", SUPABASE_KEY)
    req.add_header("Authorization", "Bearer " + SUPABASE_KEY)
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")

    if method == "POST":
        req.add_header("Prefer", "return=representation")

    with urllib.request.urlopen(req, timeout=15) as r:
        text = r.read().decode()

        if text:
            return json.loads(text)

        return None


def create_report(text):
    code = "GHD-" + secrets.token_hex(5).upper()

    db(
        "POST",
        "/rest/v1/reports",
        {
            "report": text,
            "tracking_code": code,
            "status": "جدید"
        }
    )

    return code


def reports():
    return db(
        "GET",
        "/rest/v1/reports",
        params={
            "select": "*",
            "order": "created_at.desc"
        }
    ) or []


def find_report(code):
    result = db(
        "GET",
        "/rest/v1/reports",
        params={
            "select": "*",
            "tracking_code": "eq." + code
        }
    ) or []

    return result[0] if result else None


def update_report(rid, status):
    db(
        "PATCH",
        "/rest/v1/reports",
        {"status": status},
        {"id": "eq." + str(rid)}
    )


def remove_report(rid):
    db(
        "DELETE",
        "/rest/v1/reports",
        params={"id": "eq." + str(rid)}
    )


CSS = """
*{box-sizing:border-box}
body{
margin:0;
font-family:Tahoma,Arial,sans-serif;
background:linear-gradient(135deg,#020617,#111827,#172554);
color:#fff;
min-height:100vh
}
.container{width:92%;max-width:1000px;margin:auto}
nav{
display:flex;
justify-content:space-between;
align-items:center;
padding:20px 0
}
.logo{font-size:23px;font-weight:bold}
.logo span{color:#38bdf8}
a{text-decoration:none;color:white}
.card{
background:rgba(15,23,42,.82);
border:1px solid rgba(148,163,184,.18);
border-radius:22px;
padding:25px;
margin:20px 0;
box-shadow:0 15px 45px rgba(0,0,0,.3)
}
.hero{text-align:center;padding:70px 0}
.shield{
width:100px;
height:100px;
margin:auto;
display:flex;
align-items:center;
justify-content:center;
border-radius:30px;
font-size:48px;
background:linear-gradient(135deg,#2563eb,#7c3aed);
box-shadow:0 0 40px rgba(59,130,246,.5)
}
h1{font-size:60px;margin:25px 0 10px}
h2{margin-top:0}
.sub{color:#94a3b8;line-height:2}
.buttons{
display:flex;
gap:12px;
justify-content:center;
flex-wrap:wrap;
margin-top:30px
}
.btn{
display:inline-block;
border:0;
cursor:pointer;
padding:14px 23px;
border-radius:14px;
font-weight:bold;
font-size:16px;
color:#fff;
background:linear-gradient(135deg,#2563eb,#7c3aed)
}
.secondary{background:#1e293b}
.danger{background:linear-gradient(135deg,#dc2626,#991b1b)}
input,textarea,select{
width:100%;
padding:14px;
margin:8px 0 16px;
border-radius:13px;
border:1px solid #334155;
background:#020617;
color:#fff;
font-size:16px
}
textarea{min-height:220px;resize:vertical}
.report{
white-space:pre-wrap;
line-height:1.9;
background:#020617;
padding:18px;
border-radius:14px;
margin:15px 0
}
.code{
font-size:27px;
letter-spacing:3px;
color:#38bdf8;
font-weight:bold;
margin:20px 0
}
.status{
display:inline-block;
padding:7px 13px;
border-radius:20px;
background:rgba(56,189,248,.15);
color:#38bdf8
}
.center{text-align:center}
.small{color:#64748b;font-size:13px}
footer{text-align:center;color:#64748b;padding:40px}
@media(max-width:600px){
h1{font-size:40px}
.hero{padding:45px 0}
.card{padding:18px}
}
"""


def page(title, content):
    return """<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta http-equiv="Content-Security-Policy" content="default-src 'self';style-src 'self' 'unsafe-inline';form-action 'self';frame-ancestors 'none'">
<title>""" + title + " | " + APP + """</title>
<style>""" + CSS + """</style>
</head>
<body>
<div class="container">
<nav>
<div class="logo">🛡️ <span>""" + APP + """</span></div>
<a class="btn secondary" href="/">خانه</a>
</nav>
""" + content + """
<footer>""" + APP + """</footer>
</div>
</body>
</html>"""


def home():
    return page(APP, """
<section class="hero">
<div class="shield">🛡️</div>
<h1>سامانه غدیر</h1>
<p class="sub">
سامانه آنلاین ثبت و پیگیری گزارش‌ها
<br>
ساده، سریع و قابل استفاده در دستگاه‌های مختلف
</p>

<div class="buttons">
<a class="btn" href="/report">📝 ثبت گزارش</a>
<a class="btn secondary" href="/track">🔎 پیگیری گزارش</a>
<a class="btn secondary" href="/admin">🔐 مدیریت</a>
</div>
</section>
""")


def report_page():
    return page("ثبت گزارش", """
<div class="card">
<h2>📝 ثبت گزارش</h2>
<p class="sub">رمز ثبت گزارش و متن گزارش را وارد کنید.</p>

<form method="POST" action="/submit">
<label>رمز ثبت گزارش</label>
<input type="password" name="password" required autocomplete="off">

<label>متن گزارش</label>
<textarea name="report" maxlength="10000" required></textarea>

<button class="btn" type="submit">ثبت گزارش</button>
</form>
</div>
""")


def success(code):
    return page("گزارش ثبت شد", """
<div class="card center">
<h2>✅ گزارش ثبت شد</h2>
<p class="sub">این کد پیگیری را نگه دارید:</p>
<div class="code">""" + code + """</div>
<a class="btn" href="/track?code=""" +
        urllib.parse.quote(code) + """">پیگیری گزارش</a>
</div>
""")


def track(result=None):
    extra = ""

    if result:
        if result:
            extra = """
<div class="card">
<h2>✅ گزارش پیدا شد</h2>
<p>وضعیت: <span class="status">""" + str(result.get("status", "نامشخص")) + """</span></p>
<div class="report">""" + str(result.get("report", "")) + """</div>
<p class="small">""" + str(result.get("created_at", "")) + """</p>
</div>
"""
        else:
            extra = """
<div class="card center">
<h3>❌ گزارشی با این کد پیدا نشد.</h3>
</div>
"""

    return page("پیگیری", """
<div class="card">
<h2>🔎 پیگیری گزارش</h2>

<form method="GET" action="/track">
<label>کد پیگیری</label>
<input name="code" placeholder="GHD-XXXXXXXXXX" required>
<button class="btn">پیگیری</button>
</form>
</div>
""" + extra)


def login(error=""):
    msg = ""

    if error:
        msg = '<div class="card"><p style="color:#f87171">' + error + "</p></div>"

    return page("ورود مدیریت", msg + """
<div class="card">
<h2>🔐 ورود مدیریت</h2>
<form method="POST" action="/login">
<label>رمز عبور</label>
<input type="password" name="password" required autocomplete="off">
<button class="btn">ورود</button>
</form>
</div>
""")


def admin(s):
    items = reports()
    csrf = s["csrf"]
    cards = ""

    for r in items:
        rid = str(r.get("id", ""))
        code = str(r.get("tracking_code", "بدون کد"))
        status = str(r.get("status", "جدید"))
        text = str(r.get("report", ""))

        cards += """
<div class="card">
<div class="code">""" + code + """</div>
<p><span class="status">""" + status + """</span></p>

<div class="report">""" + text + """</div>

<form method="POST" action="/status">
<input type="hidden" name="csrf" value=""" + csrf + """>
<input type="hidden" name="id" value=""" + rid + """>

<select name="status">
<option>جدید</option>
<option>در حال بررسی</option>
<option>بررسی شد</option>
<option>بسته شد</option>
</select>

<button class="btn">تغییر وضعیت</button>
</form>

<form method="POST" action="/delete">
<input type="hidden" name="csrf" value=""" + csrf + """>
<input type="hidden" name="id" value=""" + rid + """>
<button class="btn danger">حذف گزارش</button>
</form>
</div>
"""

    if not cards:
        cards = '<div class="card center"><h3>هنوز گزارشی ثبت نشده است.</h3></div>'

    return page("مدیریت", """
<div class="card">
<h2>🛡️ پنل مدیریت</h2>
<p>تعداد گزارش‌ها: <b>""" + str(len(items)) + """</b></p>
<a class="btn secondary" href="/logout">خروج</a>
</div>
""" + cards)


class Handler(BaseHTTPRequestHandler):

    def headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")

    def html(self, text, status=200, cookie=None):
        data = text.encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.headers()

        if cookie:
            self.send_header("Set-Cookie", cookie)

        self.end_headers()
        self.wfile.write(data)

    def redirect(self, location):
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def form(self):
        length = int(self.headers_get("Content-Length", "0"))

        if length > 12000:
            return {}

        raw = self.rfile.read(length).decode("utf-8", "replace")

        return urllib.parse.parse_qs(
            raw,
            keep_blank_values=True
        )

    def headers_get(self, name, default=None):
        return self.headers_data.get(name, default)

    @property
    def headers_data(self):
        return self._headers_data

    def do_GET(self):
        try:
            self._headers_data = self.headers

            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path

            if path == "/":
                self.html(home())
                return

            if path == "/report":
                self.html(report_page())
                return

            if path == "/track":
                params = urllib.parse.parse_qs(parsed.query)
                code = params.get("code", [""])[0].strip().upper()
                result = find_report(code) if code else None
                self.html(track(result))
                return

            if path == "/admin":
                s = session(self)

                if not s:
                    self.html(login())
                    return

                self.html(admin(s))
                return

            if path == "/logout":
                c = SimpleCookie()
                c.load(self.headers.get("Cookie", ""))

                if "session" in c:
                    sid = c["session"].value
                    SESSIONS.pop(sid, None)

                cookie = (
                    "session=; Path=/; Max-Age=0; "
                    "HttpOnly; Secure; SameSite=Strict"
                )

                self.html(login("از حساب خارج شدید."), cookie=cookie)
                return

            self.html(page("404", """
<div class="card center">
<h2>404</h2>
<a class="btn" href="/">بازگشت</a>
</div>
"""), 404)

        except Exception as e:
            print("GET ERROR:", repr(e))
            self.html(page("خطا", """
<div class="card center">
<h2>خطایی رخ داد.</h2>
<a class="btn" href="/">بازگشت</a>
</div>
"""), 500)

    def do_POST(self):
        try:
            self._headers_data = self.headers
            path = urllib.parse.urlparse(self.path).path
            f = self.form()

            def value(key):
                return f.get(key, [""])[0]

            if path == "/submit":
                password = value("password")
                text = value("report").strip()

                if not compare(password, REPORT_PASSWORD):
                    self.html(page("خطا", """
<div class="card center">
<h2>❌ رمز اشتباه است.</h2>
<a class="btn" href="/report">بازگشت</a>
</div>
"""), 403)
                    return

                if not text or len(text) > MAX_REPORT:
                    self.html(page("خطا", """
<div class="card center">
<h2>متن گزارش نامعتبر است.</h2>
</div>
"""), 400)
                    return

                code = create_report(text)
                self.html(success(code))
                return

            if path == "/login":
                ip = self.client_address[0]
                now = time.time()

                old = ATTEMPTS.get(ip, [])
                old = [x for x in old if now - x < 600]

                if len(old) >= 5:
                    ATTEMPTS[ip] = old
                    self.html(login("تعداد تلاش‌ها زیاد است."), 429)
                    return

                old.append(now)
                ATTEMPTS[ip] = old

                if not compare(value("password"), ADMIN_PASSWORD):
                    self.html(login("رمز عبور اشتباه است."), 403)
                    return

                sid = new_session()

                cookie = (
                    "session=" + sid +
                    "; Path=/; HttpOnly; Secure; "
                    "SameSite=Strict; Max-Age=7200"
                )

                self.html(admin(SESSIONS[sid]), cookie=cookie)
                return

            if path in ("/status", "/delete"):
                s = session(self)

                if not s:
                    self.html(login(), 403)
                    return

                if not compare(value("csrf"), s["csrf"]):
                    self.html(page("خطا", """
<div class="card center">
<h2>درخواست نامعتبر است.</h2>
</div>
"""), 403)
                    return

                rid = value("id")

                if path == "/status":
                    allowed = {
                        "جدید",
                        "در حال بررسی",
                        "بررسی شد",
                        "بسته شد"
                    }

                    status = value("status")

                    if status not in allowed:
                        self.html(page("خطا", """
<div class="card center">
<h2>وضعیت نامعتبر است.</h2>
</div>
"""), 400)
                        return

                    update_report(rid, status)

                else:
                    remove_report(rid)

                self.redirect("/admin")
                return

            self.html(page("404", "<div class='card center'><h2>404</h2></div>"), 404)

        except Exception as e:
            print("POST ERROR:", repr(e))
            self.html(page("خطا", """
<div class="card center">
<h2>خطایی در سرور رخ داد.</h2>
</div>
"""), 500)

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args))


if __name__ == "__main__":
    print(APP + " starting...")

    if not SUPABASE_URL:
        print("WARNING: SUPABASE_URL missing")

    if not SUPABASE_KEY:
        print("WARNING: SUPABASE_SECRET_KEY missing")

    if not ADMIN_PASSWORD:
        print("WARNING: ADMIN_PASSWORD missing")

    if not REPORT_PASSWORD:
        print("WARNING: REPORT_PASSWORD missing")

    server = ThreadingHTTPServer(
        ("0.0.0.0", PORT),
        Handler
    )

    print("Server running on port", PORT)
    server.serve_forever()
