import os
import time
import secrets
import hmac
import urllib.parse
import urllib.request
import json
import html

from http.server import BaseHTTPRequestHandler, HTTPServer


# =========================================================
# تنظیمات
# =========================================================

PORT = int(os.getenv("PORT", "10000"))

SUPABASE_URL = os.getenv(
    "SUPABASE_URL",
    ""
).rstrip("/")

SUPABASE_KEY = os.getenv(
    "SUPABASE_SECRET_KEY",
    "")

ADMIN_USERNAME = os.getenv(
    "ADMIN_USERNAME",
    "admin"
)

ADMIN_PASSWORD = os.getenv(
    "ADMIN_PASSWORD",
    ""
)

REPORT_PASSWORD = os.getenv(
    "REPORT_PASSWORD",
    ""
)

SESSION_TTL = 2 * 60 * 60

MAX_REPORT_LENGTH = 10000


# =========================================================
# حافظه نشست‌ها
# =========================================================

SESSIONS = {}

LOGIN_ATTEMPTS = {}


# =========================================================
# ابزارها
# =========================================================

def esc(value):
    return html.escape(
        str(value),
        quote=True
    )


# =========================================================
# Cookie
# =========================================================

def get_cookies(handler):

    result = {}

    header = handler.headers.get(
        "Cookie",
        ""
    )

    for part in header.split(";"):

        if "=" not in part:
            continue

        name, value = part.strip().split(
            "=",
            1
        )

        result[name] = value

    return result


# =========================================================
# Session
# =========================================================

def create_session():

    token = secrets.token_urlsafe(32)

    csrf = secrets.token_urlsafe(32)

    SESSIONS[token] = {

        "csrf": csrf,

        "expires":
            time.time() + SESSION_TTL
    }

    return token, csrf


def get_session(handler):

    token = get_cookies(
        handler
    ).get(
        "session"
    )

    if not token:
        return None, None

    session = SESSIONS.get(
        token
    )

    if not session:
        return None, None

    if session["expires"] < time.time():

        SESSIONS.pop(
            token,
            None
        )

        return None, None

    return token, session


# =========================================================
# Supabase
# =========================================================

def supabase(
    method,
    path,
    data=None
):

    if not SUPABASE_URL:

        raise RuntimeError(
            "SUPABASE_URL تنظیم نشده است."
        )

    if not SUPABASE_KEY:

        raise RuntimeError(
            "SUPABASE_SECRET_KEY تنظیم نشده است."
        )

    body = None

    if data is not None:

        body = json.dumps(
            data
        ).encode(
            "utf-8"
        )

    request = urllib.request.Request(

        SUPABASE_URL + path,

        data=body,

        method=method,

        headers={

            "apikey":
                SUPABASE_KEY,

            "Authorization":
                "Bearer " + SUPABASE_KEY,

            "Content-Type":
                "application/json",

            "Prefer":
                "return=representation"
        }
    )

    with urllib.request.urlopen(
        request,
        timeout=15
    ) as response:

        raw = response.read().decode(
            "utf-8"
        )

        if not raw:
            return []

        return json.loads(
            raw
        )


# =========================================================
# قالب سایت
# =========================================================

def page(
    title,
    content
):

    return f"""
<!doctype html>

<html
lang="fa"
dir="rtl"
>

<head>

<meta charset="utf-8">

<meta
name="viewport"
content="width=device-width,initial-scale=1"
>

<title>
{esc(title)}
|
سامانه غدیر
</title>

<style>

* {{
    box-sizing: border-box;
}}

body {{

    margin: 0;

    min-height: 100vh;

    font-family:
        Tahoma,
        Arial,
        sans-serif;

    color: #f5f7fb;

    background:

        radial-gradient(
            circle at 15% 10%,
            #17315e 0,
            transparent 35%
        ),

        radial-gradient(
            circle at 90% 90%,
            #3a185c 0,
            transparent 35%
        ),

        #070b14;
}}


a {{
    text-decoration: none;
    color: inherit;
}}


.wrap {{

    width: min(
        94%,
        900px
    );

    margin: auto;

    padding:
        22px 0 40px;
}}


/* =========================
   نوار بالا
========================= */

.top {{

    display: flex;

    align-items: center;

    justify-content:
        space-between;

    padding:
        12px 16px;

    margin-bottom:
        18px;

    border:
        1px solid #26334b;

    background:
        #0d1422cc;

    border-radius:
        20px;

    backdrop-filter:
        blur(12px);
}}


.brand {{

    display: flex;

    gap: 11px;

    align-items:
        center;

    font-weight:
        bold;
}}


.brand i {{

    width: 42px;

    height: 42px;

    display: grid;

    place-items:
        center;

    border-radius:
        13px;

    background:
        linear-gradient(
            135deg,
            #2563eb,
            #7c3aed
        );

    font-style:
        normal;

    font-size:
        22px;
}}


.online {{

    font-size:
        11px;

    color:
        #7ee7aa;
}}


/* =========================
   کارت
========================= */

.card {{

    background:
        #0d1422e8;

    border:
        1px solid #25324a;

    border-radius:
        25px;

    padding:
        25px;

    margin-bottom:
        16px;

    box-shadow:
        0 20px 60px #0007;
}}


/* =========================
   ورود
========================= */

.login {{

    max-width:
        500px;

    margin:
        7vh auto;
}}


/* =========================
   متن
========================= */

h1 {{

    font-size:
        30px;

    margin:
        8px 0;
}}


h2 {{

    margin-top:
        0;
}}


p {{

    line-height:
        1.9;

    color:
        #aab6c9;
}}


/* =========================
   فرم
========================= */

label {{

    display:
        block;

    margin:
        13px 0 7px;

    color:
        #dce5f4;

    font-weight:
        bold;
}}


input,
textarea,
select {{

    width:
        100%;

    padding:
        14px 15px;

    border-radius:
        14px;

    border:
        1px solid #2a3850;

    background:
        #111a2a;

    color:
        white;

    outline:
        0;

    font:
        inherit;
}}


input:focus,
textarea:focus,
select:focus {{

    border-color:
        #4f8cff;

    box-shadow:
        0 0 0 3px
        #3b82f622;
}}


textarea {{

    min-height:
        190px;

    resize:
        vertical;

    line-height:
        1.8;
}}


/* =========================
   دکمه
========================= */

button,
.btn {{

    display:
        block;

    width:
        100%;

    border:
        0;

    border-radius:
        14px;

    padding:
        14px;

    margin-top:
        10px;

    text-align:
        center;

    font-weight:
        bold;

    font-size:
        15px;

    color:
        white;

    background:
        linear-gradient(
            135deg,
            #2563eb,
            #7c3aed
        );

    cursor:
        pointer;
}}


.dark {{

    background:
        #172033;

    border:
        1px solid #2b3951;
}}


.danger {{

    background:
        linear-gradient(
            135deg,
            #b42323,
            #7f1d1d
        );
}}


/* =========================
   گزینه‌های داشبورد
========================= */

.grid {{

    display:
        grid;

    grid-template-columns:
        repeat(3, 1fr);

    gap:
        12px;
}}


.action {{

    padding:
        22px;

    border-radius:
        20px;

    background:
        #111a2a;

    border:
        1px solid #263650;

    transition:
        .2s;
}}


.action:hover {{

    transform:
        translateY(-3px);

    border-color:
        #5277bd;
}}


.icon {{

    font-size:
        30px;
}}


.title {{

    font-weight:
        bold;

    margin-top:
        10px;
}}


.small {{

    font-size:
        12px;

    color:
        #8998ad;
}}


/* =========================
   مرکز
========================= */

.center {{

    text-align:
        center;
}}


/* =========================
   کد پیگیری
========================= */

.code {{

    direction:
        ltr;

    text-align:
        center;

    font-weight:
        bold;

    letter-spacing:
        2px;

    color:
        #ffd75a;

    background:
        #070b12;

    border:
        1px dashed #80691e;

    border-radius:
        14px;

    padding:
        15px;

    margin:
        14px 0;

    font-size:
        21px;
}}


/* =========================
   وضعیت
========================= */

.status {{

    display:
        inline-block;

    padding:
        7px 12px;

    border-radius:
        99px;

    background:
        #17335e;

    color:
        #a9c9ff;

    font-size:
        12px;
}}


/* =========================
   گزارش
========================= */

.report {{

    white-space:
        pre-wrap;

    line-height:
        2;

    background:
        #080d16;

    border:
        1px solid #202c40;

    padding:
        16px;

    border-radius:
        15px;

    margin-top:
        12px;
}}


/* =========================
   پیام‌ها
========================= */

.ok,
.err {{

    padding:
        13px;

    border-radius:
        14px;

    margin-bottom:
        12px;
}}


.ok {{

    background:
        #123a26;

    border:
        1px solid #246b42;
}}


.err {{

    background:
        #3a171b;

    border:
        1px solid #743038;
}}


/* =========================
   آمار
========================= */

.stats {{

    display:
        grid;

    grid-template-columns:
        repeat(3, 1fr);

    gap:
        10px;

    margin-bottom:
        15px;
}}


.stat {{

    background:
        #111a2a;

    border:
        1px solid #263650;

    border-radius:
        16px;

    padding:
        15px;

    text-align:
        center;
}}


.num {{

    font-size:
        26px;

    font-weight:
        bold;

    color:
        #b9d2ff;
}}


/* =========================
   موبایل
========================= */

@media(
    max-width:650px
) {{

    .grid,
    .stats {{

        grid-template-columns:
            1fr;
    }}

    .card {{

        padding:
            19px;
    }}

    h1 {{

        font-size:
            25px;
    }}

    .top {{

        border-radius:
            16px;
    }}
}}

</style>

</head>


<body>

<div class="wrap">


<div class="top">

<div class="brand">

<i>
🛡️
</i>

<div>

سامانه غدیر

<br>

<span class="small">
ثبت و پیگیری گزارش
</span>

</div>

</div>


<span class="online">
● آنلاین
</span>

</div>


{content}


</div>

</body>

</html>
"""


# =========================================================
# ارسال HTML
# =========================================================

def send_html(
    handler,
    body,
    status=200
):

    data = body.encode(
        "utf-8"
    )

    handler.send_response(
        status
    )

    handler.send_header(
        "Content-Type",
        "text/html; charset=utf-8"
    )

    handler.send_header(
        "Content-Length",
        str(len(data))
    )

    handler.send_header(
        "Cache-Control",
        "no-store"
    )

    handler.send_header(
        "X-Content-Type-Options",
        "nosniff"
    )

    handler.send_header(
        "X-Frame-Options",
        "DENY"
    )

    handler.send_header(
        "Referrer-Policy",
        "no-referrer"
    )

    handler.send_header(
        "Content-Security-Policy",
        "default-src 'self'; "
        "style-src 'unsafe-inline'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    )

    handler.end_headers()

    handler.wfile.write(
        data
    )


# =========================================================
# صفحه ورود
# =========================================================

def login_page(
    error=""
):

    error_html = ""

    if error:

        error_html = f"""
<div class="err">
{esc(error)}
</div>
"""


    return page(

        "ورود",

        f"""

<div class="card login center">

<div
style="font-size:54px"
>
🛡️
</div>


<h1>
ورود به سامانه غدیر
</h1>


<p>
برای ورود، نام کاربری و گذرواژه
خود را وارد کنید.
</p>


{error_html}


<form
method="post"
action="/login"
>


<label>
نام کاربری
</label>


<input
name="username"
autocomplete="username"
required
placeholder="نام کاربری"
>


<label>
گذرواژه
</label>


<input
type="password"
name="password"
autocomplete="current-password"
required
placeholder="گذرواژه"
>


<button
type="submit"
>
🔐 ورود به سامانه
</button>


</form>

</div>

"""
    )


# =========================================================
# داشبورد
# =========================================================

def dashboard():

    return page(

        "داشبورد",

        """

<div class="card center">

<h2>
خوش آمدید 👋
</h2>


<p>
از بخش موردنظر خود استفاده کنید.
</p>


<div class="grid">


<a
class="action"
href="/report"
>

<div class="icon">
📝
</div>

<div class="title">
ثبت گزارش
</div>

<div class="small">
ارسال گزارش جدید
</div>

</a>


<a
class="action"
href="/track"
>

<div class="icon">
🔎
</div>

<div class="title">
پیگیری گزارش
</div>

<div class="small">
پیگیری با کد
</div>

</a>


<a
class="action"
href="/reports"
>

<div class="icon">
📋
</div>

<div class="title">
مدیریت گزارش‌ها
</div>

<div class="small">
مشاهده و مدیریت
</div>

</a>


</div>


<a
class="btn dark"
href="/logout"
>

🚪 خروج

</a>

</div>

"""
    )


# =========================================================
# صفحه ثبت گزارش
# =========================================================

def report_page(
    error=""
):

    error_html = ""

    if error:

        error_html = f"""
<div class="err">
{esc(error)}
</div>
"""


    return page(

        "ثبت گزارش",

        f"""

<div class="card">

<h2>
📝 ثبت گزارش جدید
</h2>


<p>
گزارش را وارد کنید و پس از ثبت،
کد پیگیری دریافت می‌کنید.
</p>


{error_html}


<form
method="post"
action="/submit"
>


<label>
متن گزارش
</label>


<textarea
name="report"
maxlength="10000"
required
placeholder="متن گزارش را اینجا وارد کنید..."
></textarea>


<label>
رمز ثبت گزارش
</label>


<input
type="password"
name="password"
required
placeholder="رمز ثبت گزارش"
>


<button
type="submit"
>
🚀 ثبت گزارش
</button>


<a
class="btn dark"
href="/"
>
بازگشت
</a>


</form>

</div>

"""
    )


# =========================================================
# صفحه پیگیری
# =========================================================

def track_page(
    error=""
):

    error_html = ""

    if error:

        error_html = f"""
<div class="err">
{esc(error)}
</div>
"""


    return page(

        "پیگیری",

        f"""

<div class="card">

<h2>
🔎 پیگیری گزارش
</h2>


<p>
کد پیگیری خود را وارد کنید.
</p>


{error_html}


<form
method="get"
action="/track"
>


<label>
کد پیگیری
</label>


<input
name="code"
required
placeholder="GHD-XXXXXXXXXX"
>


<button
type="submit"
>
🔎 پیگیری
</button>


<a
class="btn dark"
href="/"
>
بازگشت
</a>


</form>

</div>

"""
    )


# =========================================================
# پیدا کردن گزارش
# =========================================================

def find_report(
    code
):

    encoded = urllib.parse.quote(
        code,
        safe=""
    )

    rows = supabase(

        "GET",

        "/rest/v1/reports"
        "?tracking_code=eq."
        + encoded
        + "&select=*"
    )

    if rows:

        return rows[0]

    return None


# =========================================================
# صفحه مدیریت گزارش‌ها
# =========================================================

def reports_page(
    handler
):

    token, session = get_session(
        handler
    )

    if not session:

        return login_page(
            "ابتدا وارد سامانه شوید."
        )


    rows = supabase(

        "GET",

        "/rest/v1/reports"
        "?select=*"
        "&order=id.desc"
    )


    new_count = sum(

        1

        for row in rows

        if row.get(
            "status",
            "جدید"
        ) == "جدید"
    )


    checking_count = sum(

        1

        for row in rows

        if row.get(
            "status",
            ""
        ) == "در حال بررسی"
    )


    done_count = sum(

        1

        for row in rows

        if row.get(
            "status",
            ""
        ) in {
            "بررسی شد",
            "بررسی‌شده",
            "بسته شد"
        }
    )


    cards = ""


    for row in rows:

        report_id = esc(
            row.get(
                "id",
                ""
            )
        )


        code = esc(
            row.get(
                "tracking_code",
                ""
            )
        )


        status = esc(
            row.get(
                "status",
                "جدید"
            )
        )


        text = esc(
            row.get(
                "report",
                ""
            )
        )


        created = esc(
            row.get(
                "created_at",
                ""
            )
        )


        csrf = esc(
            session["csrf"]
        )


        cards += f"""

<div class="card">


<span class="status">
وضعیت: {status}
</span>


<div class="code">
{code}
</div>


<div class="small">
زمان ثبت: {created}
</div>


<div class="report">
{text}
</div>


<form
method="post"
action="/status"
>


<input
type="hidden"
name="csrf"
value="{csrf}"
>


<input
type="hidden"
name="id"
value="{report_id}"
>


<label>
وضعیت جدید
</label>


<select
name="status"
>

<option>
جدید
</option>

<option>
در حال بررسی
</option>

<option>
بررسی شد
</option>

<option>
بسته شد
</option>

</select>


<button
type="submit"
>
💾 ذخیره وضعیت
</button>


</form>


<form
method="post"
action="/delete"
>


<input
type="hidden"
name="csrf"
value="{csrf}"
>


<input
type="hidden"
name="id"
value="{report_id}"
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

<div class="card center">

<h2>
📭
</h2>

<p>
هنوز گزارشی ثبت نشده است.
</p>

</div>

"""


    return page(

        "مدیریت گزارش‌ها",

        f"""

<div class="stats">


<div class="stat">

<div class="num">
{len(rows)}
</div>

کل گزارش‌ها

</div>


<div class="stat">

<div class="num">
{new_count}
</div>

گزارش جدید

</div>


<div class="stat">

<div class="num">
{checking_count + done_count}
</div>

بررسی‌شده

</div>


</div>


{cards}


<div class="card">

<a
class="btn dark"
href="/"
>
🏠 داشبورد
</a>

</div>

"""
    )


# =========================================================
# Handler
# =========================================================

class Handler(
    BaseHTTPRequestHandler
):


    # =====================================================
    # خواندن POST
    # =====================================================

    def read_form(self):

        length = int(
            self.headers.get(
                "Content-Length",
                "0"
            )
        )


        if length > 15000:

            return {}


        body = self.rfile.read(
            length
        ).decode(
            "utf-8",
            errors="replace"
        )


        return urllib.parse.parse_qs(
            body,
            keep_blank_values=True
        )


    # =====================================================
    # Redirect
    # =====================================================

    def redirect(
        self,
        path,
        cookie=None
    ):

        self.send_response(
            303
        )

        self.send_header(
            "Location",
            path
        )

        self.send_header(
            "Cache-Con
