from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs
import html

گزارش‌ها = []

صفحه = """
<!DOCTYPE html>
<html lang="fa">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>سامانه گزارش امن</title>
<style>
body {
    font-family: Arial;
    direction: rtl;
    padding: 25px;
    background: #f2f2f2;
}
.box {
    max-width: 500px;
    margin: auto;
    background: white;
    padding: 20px;
    border-radius: 15px;
}
textarea {
    width: 100%;
    height: 180px;
    font-size: 17px;
}
button {
    margin-top: 15px;
    padding: 12px 25px;
    font-size: 17px;
}
</style>
</head>

<body>

<div class="box">
<h1>🔐 سامانه گزارش امن</h1>

<form method="POST">
<textarea name="report"
placeholder="گزارش خود را بنویسید..."></textarea>

<br>

<button type="submit">ثبت گزارش</button>
</form>

</div>

</body>
</html>
"""


class Server(BaseHTTPRequestHandler):

    def do_GET(self):

        self.send_response(200)
        self.send_header(
            "Content-Type",
            "text/html; charset=utf-8"
        )
        self.end_headers()

        self.wfile.write(
            صفحه.encode("utf-8")
        )

    def do_POST(self):

        طول = int(
            self.headers.get("Content-Length", 0)
        )

        داده = self.rfile.read(طول).decode("utf-8")

        اطلاعات = parse_qs(داده)

        گزارش = اطلاعات.get(
            "report",
            [""]
        )[0]

        گزارش = html.escape(
            گزارش.strip()
        )

        if گزارش:

            گزارش‌ها.append(گزارش)

            with open(
                "online_reports.txt",
                "a",
                encoding="utf-8"
            ) as فایل:

                فایل.write(
                    گزارش + "\n"
                )

        self.send_response(200)
        self.send_header(
            "Content-Type",
            "text/html; charset=utf-8"
        )
        self.end_headers()

        پیام = """
        <html>
        <body dir="rtl">
        <h2>✅ گزارش با موفقیت ثبت شد.</h2>
        <a href="/">بازگشت</a>
        </body>
        </html>
        """

        self.wfile.write(
            پیام.encode("utf-8")
        )

import os

PORT = int(os.environ.get("PORT", 8080))

سرور = HTTPServer(
    ("0.0.0.0", PORT),
    Server
)

print("🌐 سامانه آنلاین اجرا شد.")
print("http://127.0.0.1:8080")

سرور.serve_forever()