from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs
import html
import os
import secrets
import hmac

گزارش‌ها = []

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "1234")
SESSION_TOKEN = secrets.token_urlsafe(32)

صفحه_اصلی = """
<!DOCTYPE html>
<html lang="fa">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>سامانه گزارش</title>
<style>
body{font-family:Arial;direction:rtl;background:#f2f2f2;padding:25px}
.box{max-width:500px;margin:auto;background:white;padding:20px;border-radius:15px}
textarea{width:100%;height:180px;font-size:17px}
button{margin-top:15px;padding:12px 25px;font-size:17px}
a{display:block;margin-top:20px}
</style>
</head>
<body>
<div class="box">
<h1>🔐 سامانه گزارش</h1>

<form method="POST" action="/report">
<textarea name="report" placeholder="گزارش خود را بنویسید..."></textarea>
<br>
<button type="submit">ثبت گزارش</button>
</form>

<a href="/admin">ورود مدیریت</a>
</div>
</body>
</html>
"""


def صفحه_مدیریت():
    متن = "<h1>📋 گزارش‌ها</h1>"

    if not گزارش‌ها:
        متن += "<p>هنوز گزارشی ثبت نشده است.</p>"

    for شماره, گزارش in enumerate(گزارش‌ها, 1):
        متن += f"""
        <div style="background:white;padding:15px;margin:10px 0;border-radius:10px">
        <b>گزارش {شماره}</b>
        <p>{گزارش}</p>
        </div>
        """

    return f"""
    <!DOCTYPE html>
    <html lang="fa">
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>مدیریت</title>
    </head>
    <body dir="rtl" style="font-family:Arial;background:#f2f2f2;padding:20px">
    {متن}
    <a href="/">بازگشت</a>
    </body>
    </html>
    """


class Server(BaseHTTPRequestHandler):

    def do_GET(self):

        if self.path == "/":
            self.send_html(صفحه_اصلی)
            return

        if self.path == "/admin":
            self.send_html("""
            <!DOCTYPE html>
            <html lang="fa">
            <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            </head>
            <body dir="rtl" style="font-family:Arial;padding:30px">
            <h2>🔐 ورود مدیریت</h2>

            <form method="POST" action="/login">
            <input type="password" name="password"
            placeholder="رمز عبور"
            style="padding:12px;font-size:18px">

            <br><br>
            <button style="padding:12px 25px">
            ورود
            </button>
            </form>

            </body>
            </html>
            """)
            return

        if self.path == "/reports":

            if self.headers.get("Cookie") == "session=" + SESSION_TOKEN:
                self.send_html(صفحه_مدیریت())
            else:
                self.send_response(403)
                self.end_headers()
                self.wfile.write("دسترسی غیرمجاز".encode("utf-8"))

            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):

        طول = int(self.headers.get("Content-Length", 0))
        داده = self.rfile.read(طول).decode("utf-8")
        اطلاعات = parse_qs(داده)

        if self.path == "/report":

            گزارش = اطلاعات.get("report", [""])[0].strip()

            if گزارش:
                گزارش‌ها.append(html.escape(گزارش))

                with open(
                    "online_reports.txt",
                    "a",
                    encoding="utf-8"
                ) as فایل:
                    فایل.write(گزارش + "\n")

            self.send_html("""
            <html>
            <body dir="rtl" style="font-family:Arial;padding:30px">
            <h2>✅ گزارش با موفقیت ثبت شد.</h2>
            <a href="/">بازگشت</a>
            </body>
            </html>
            """)
            return

        if self.path == "/login":

            رمز = اطلاعات.get("password", [""])[0]

            if hmac.compare_digest(رمز, ADMIN_PASSWORD):

                self.send_response(302)
                self.send_header(
                    "Location",
                    "/reports"
                )
                self.send_header(
                    "Set-Cookie",
                    "session=" + SESSION_TOKEN +
                    "; HttpOnly; Secure; SameSite=Strict"
                )
                self.end_headers()

            else:

                self.send_html("""
                <html>
                <body dir="rtl" style="font-family:Arial;padding:30px">
                <h2>❌ رمز اشتباه است.</h2>
                <a href="/admin">تلاش دوباره</a>
                </body>
                </html>
                """)

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
        )


PORT = int(os.environ.get("PORT", 8080))

سرور = HTTPServer(
    ("0.0.0.0", PORT),
    Server
)

print("سامانه اجرا شد")

سرور.serve_forever()
