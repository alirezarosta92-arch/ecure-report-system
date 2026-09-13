from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs
import urllib.request
import json
import html
import os
import secrets
import hmac

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
SUPABASE_URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
SUPABASE_SECRET_KEY = os.environ.get("SUPABASE_SECRET_KEY", "")

SESSION_TOKEN = secrets.token_urlsafe(32)


def supabase_request(method, url, data=None):

    headers = {
        "apikey": SUPABASE_SECRET_KEY,
        "Authorization": "Bearer " + SUPABASE_SECRET_KEY,
        "Content-Type": "application/json"
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

    with urllib.request.urlopen(request, timeout=15) as response:
        text = response.read().decode("utf-8")

        if text:
            return json.loads(text)

        return None


صفحه_اصلی = """
<!DOCTYPE html>
<html lang="fa">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">

<title>سامانه گزارش</title>

<style>

*{
    box-sizing:border-box;
}

body{
    margin:0;
    font-family:Tahoma,Arial,sans-serif;
    direction:rtl;
    min-height:100vh;

    background:
    radial-gradient(circle at top,#263b70,#111827 55%,#070b14);

    color:white;
    display:flex;
    align-items:center;
    justify-content:center;
    padding:20px;
}

.container{
    width:100%;
    max-width:520px;
}

.card{
    background:rgba(255,255,255,0.09);
    backdrop-filter:blur(18px);
    border:1px solid rgba(255,255,255,0.15);
    border-radius:25px;
    padding:28px;

    box-shadow:
    0 20px 60px rgba(0,0,0,0.35);
}

.logo{
    width:75px;
    height:75px;

    margin:0 auto 15px;

    border-radius:22px;

    display:flex;
    align-items:center;
    justify-content:center;

    font-size:38px;

    background:linear-gradient(
        135deg,
        #4f8cff,
        #7c3aed
    );

    box-shadow:
    0 10px 30px rgba(79,140,255,0.35);
}

h1{
    text-align:center;
    margin:10px 0 8px;
    font-size:27px;
}

.subtitle{
    text-align:center;
    color:#cbd5e1;
    margin-bottom:25px;
    font-size:14px;
}

textarea{
    width:100%;
    min-height:190px;

    resize:vertical;

    border:none;
    outline:none;

    border-radius:17px;

    padding:17px;

    font-family:Tahoma,Arial,sans-serif;
    font-size:16px;

    background:rgba(255,255,255,0.95);
    color:#111827;
}

textarea:focus{
    box-shadow:
    0 0 0 3px rgba(79,140,255,0.35);
}

button{
    width:100%;

    border:none;
    border-radius:15px;

    padding:15px;

    margin-top:15px;

    font-family:Tahoma,Arial,sans-serif;
    font-size:17px;
    font-weight:bold;

    color:white;

    cursor:pointer;

    background:linear-gradient(
        135deg,
        #4f8cff,
        #7c3aed
    );

    box-shadow:
    0 8px 25px rgba(79,140,255,0.3);
}

button:active{
    transform:scale(0.98);
}

.admin{
    display:block;
    text-align:center;
    margin-top:22px;
    color:#bfdbfe;
    text-decoration:none;
    font-size:14px;
}

.footer{
    text-align:center;
    margin-top:18px;
    color:#94a3b8;
    font-size:12px;
}

</style>
</head>

<body>

<div class="container">

<div class="card">

<div class="logo">
🔐
</div>

<h1>
سامانه گزارش
</h1>

<div class="subtitle">
گزارش خود را ثبت کنید
</div>

<form method="POST" action="/report">

<textarea
name="report"
placeholder="گزارش خود را اینجا بنویسید..."
required
></textarea>

<button type="submit">
ثبت گزارش
</button>

</form>

<a class="admin" href="/admin">
🔑 ورود مدیریت
</a>

<div class="footer">
سامانه گزارش آنلاین
</div>

</div>

</div>

</body>
</html>
"""


def صفحه_مدیریت():

    try:

        url = (
            SUPABASE_URL
            + "/rest/v1/reports"
            + "?select=id,created_at,report"
            + "&order=id.asc"
        )

        گزارش‌ها = supabase_request(
            "GET",
            url
        )

    except Exception:

        return """
        <html>
        <body dir="rtl"
        style="font-family:Tahoma;padding:30px">

        <h2>❌ خطا در دریافت گزارش‌ها</h2>

        <p>
        اتصال به پایگاه داده برقرار نشد.
        </p>

        <a href="/admin">
        بازگشت
        </a>

        </body>
        </html>
        """

    کارت‌ها = ""

    if not گزارش‌ها:

        کارت‌ها = """
        <div class="empty">
        📭
        <br><br>
        هنوز گزارشی ثبت نشده است.
        </div>
        """

    else:

        for شماره, گزارش in enumerate(گزارش‌ها, 1):

            متن = html.escape(
                str(
                    گزارش.get(
                        "report",
                        ""
                    )
                )
            )

            زمان = html.escape(
                str(
                    گزارش.get(
                        "created_at",
                        ""
                    )
                )
            )

            کارت‌ها += f"""

            <div class="report">

                <div class="report-title">
                    📄 گزارش {شماره}
                </div>

                <div class="report-text">
                    {متن}
                </div>

                <div class="date">
                    🕒 {زمان}
                </div>

            </div>

            """

    return f"""

    <!DOCTYPE html>

    <html lang="fa">

    <head>

    <meta charset="UTF-8">

    <meta name="viewport"
    content="width=device-width, initial-scale=1">

    <title>مدیریت گزارش‌ها</title>

    <style>

    *{{
        box-sizing:border-box;
    }}

    body{{
        margin:0;
        direction:rtl;
        font-family:Tahoma,Arial;
        background:#0f172a;
        color:white;
        padding:20px;
    }}

    .container{{
        max-width:700px;
        margin:auto;
    }}

    .header{{
        background:linear-gradient(
            135deg,
            #2563eb,
            #7c3aed
        );

        padding:25px;
        border-radius:22px;
        margin-bottom:20px;
    }}

    .header h1{{
        margin:0 0 8px;
        font-size:25px;
    }}

    .header p{{
        margin:0;
        color:#dbeafe;
        font-size:14px;
    }}

    .report{{
        background:#1e293b;
        border:1px solid #334155;
        border-radius:18px;
        padding:18px;
        margin-bottom:15px;
    }}

    .report-title{{
        font-weight:bold;
        color:#93c5fd;
        margin-bottom:15px;
    }}

    .report-text{{
        background:#0f172a;
        padding:15px;
        border-radius:13px;
        line-height:1.9;
        white-space:pre-wrap;
        overflow-wrap:anywhere;
    }}

    .date{{
        color:#94a3b8;
        font-size:11px;
        margin-top:12px;
    }}

    .empty{{
        background:#1e293b;
        border-radius:18px;
        padding:40px;
        text-align:center;
        color:#94a3b8;
    }}

    .back{{
        display:block;
        text-align:center;
        color:#93c5fd;
        text-decoration:none;
        margin-top:25px;
    }}

    </style>

    </head>

    <body>

    <div class="container">

        <div class="header">

            <h1>
            📋 مدیریت گزارش‌ها
            </h1>

            <p>
            گزارش‌های ذخیره‌شده در سامانه
            </p>

        </div>

        {کارت‌ها}

        <a class="back" href="/">
        ← بازگشت به صفحه اصلی
        </a>

    </div>

    </body>

    </html>

    """


class Server(BaseHTTPRequestHandler):

    def do_GET(self):

        if self.path == "/":

            self.send_html(
                صفحه_اصلی
            )

            return

        if self.path == "/admin":

            self.send_html("""

            <!DOCTYPE html>

            <html lang="fa">

            <head>

            <meta charset="UTF-8">

            <meta name="viewport"
            content="width=device-width, initial-scale=1">

            <title>ورود مدیریت</title>

            <style>

            body{
                margin:0;
                direction:rtl;
                font-family:Tahoma;
                min-height:100vh;

                background:
                linear-gradient(
                    135deg,
                    #111827,
                    #312e81
                );

                display:flex;
                align-items:center;
                justify-content:center;

                padding:20px;
            }

            .box{
                width:100%;
                max-width:400px;

                background:rgba(255,255,255,0.1);

                backdrop-filter:blur(15px);

                padding:30px;

                border-radius:25px;

                color:white;

                text-align:center;
            }

            input{
                width:100%;
                box-sizing:border-box;

                padding:15px;

                border:0;
                outline:0;

                border-radius:14px;

                font-size:17px;

                margin-top:20px;
            }

            button{
                width:100%;

                padding:14px;

                margin-top:15px;

                border:0;
                border-radius:14px;

                color:white;

                font-size:17px;
                font-weight:bold;

                background:linear-gradient(
                    135deg,
                    #4f8cff,
                    #7c3aed
                );
            }

            a{
                display:block;
                color:#bfdbfe;
                margin-top:20px;
                text-decoration:none;
            }

            </style>

            </head>

            <body>

            <div class="box">

            <div style="font-size:45px">
            🔐
            </div>

            <h2>
            ورود مدیریت
            </h2>

            <p>
            رمز مدیریت را وارد کنید
            </p>

            <form method="POST" action="/login">

            <input
            type="password"
            name="password"
            placeholder="رمز عبور"
            required
            >

            <button>
            ورود به مدیریت
            </button>

            </form>

            <a href="/">
            ← بازگشت
            </a>

            </div>

            </body>

            </html>

            """)

            return

        if self.path == "/reports":

            cookie = self.headers.get(
                "Cookie",
                ""
            )

            if cookie == "session=" + SESSION_TOKEN:

                self.send_html(
                    صفحه_مدیریت()
                )

            else:

                self.send_response(403)

                self.end_headers()

                self.wfile.write(
                    "دسترسی غیرمجاز".encode(
                        "utf-8"
                    )
                )

            return

        self.send_response(404)
        self.end_headers()


    def do_POST(self):

        طول = int(
            self.headers.get(
                "Content-Length",
                0
            )
        )

        داده = self.rfile.read(
            طول
        ).decode("utf-8")

        اطلاعات = parse_qs(
            داده
        )


        if self.path == "/report":

            گزارش = اطلاعات.get(
                "report",
                [""]
            )[0].strip()


            if not گزارش:

                self.send_html("""
                <html>
                <body dir="rtl"
                style="font-family:Tahoma;padding:30px">

                <h2>⚠️ گزارش خالی است.</h2>

                <a href="/">بازگشت</a>

                </body>
                </html>
                """)

                return


            try:

                url = (
                    SUPABASE_URL
                    + "/rest/v1/reports"
                )

                supabase_request(
                    "POST",
                    url,
                    {
                        "report": گزارش
                    }
                )

                self.send_html("""

                <html>

                <head>

                <meta
                name="viewport"
                content="width=device-width,initial-scale=1"
                >

                </head>

                <body
                dir="rtl"
                style="
                font-family:Tahoma;
                background:#0f172a;
                color:white;
                text-align:center;
                padding:60px 20px;
                ">

                <div style="
                background:#1e293b;
                padding:30px;
                border-radius:25px;
                max-width:450px;
                margin:auto;
                ">

                <div style="font-size:55px">
                ✅
                </div>

                <h2>
                گزارش ثبت شد
                </h2>

                <p style="color:#94a3b8">
                گزارش شما با موفقیت ذخیره شد.
                </p>

                <a
                href="/"
                style="
                color:#93c5fd;
                text-decoration:none;
                ">

                بازگشت به صفحه اصلی

                </a>

                </div>

                </body>

                </html>

                """)

            except Exception:

                self.send_html("""

                <html>

                <body
                dir="rtl"
                style="
                font-family:Tahoma;
                padding:30px
                ">

                <h2>
                ❌ ثبت گزارش ناموفق بود.
                </h2>

                <p>
                اتصال به پایگاه داده برقرار نشد.
                </p>

                <a href="/">
                بازگشت
                </a>

                </body>

                </html>

                """)

            return


        if self.path == "/login":

            رمز = اطلاعات.get(
                "password",
                [""]
            )[0]


            if hmac.compare_digest(
                رمز,
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

                self.send_html("""

                <html>

                <body
                dir="rtl"
                style="
                font-family:Tahoma;
                padding:30px
                ">

                <h2>
                ❌ رمز اشتباه است.
                </h2>

                <a href="/admin">
                تلاش دوباره
                </a>

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


PORT = int(
    os.environ.get(
        "PORT",
        8080
    )
)

سرور = HTTPServer(
    ("0.0.0.0", PORT),
    Server
)

print("سامانه اجرا شد")

سرور.serve_forever()
