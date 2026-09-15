import os,json,time,secrets,hmac,urllib.request,urllib.parse
from http.server import BaseHTTPRequestHandler,HTTPServer

PORT=int(os.getenv('PORT','10000'))
URL=os.getenv('SUPABASE_URL','').rstrip('/')
KEY=os.getenv('SUPABASE_SECRET_KEY','')
ADMIN=os.getenv('ADMIN_PASSWORD','')
REPORT=os.getenv('REPORT_PASSWORD','')

sessions={}
attempts={}
TTL=7200
MAX=10000

def esc(x):
    return ('' if x is None else str(x)).replace('&','&amp;').replace('<','&lt;').replace('>','&gt;').replace('"','&quot;').replace("'",'&#x27;')

def db(method,path,data=None):
    req=urllib.request.Request(
        URL+path,
        headers={
            'apikey':KEY,
            'Authorization':'Bearer '+KEY,
            'Content-Type':'application/json',
            'Accept':'application/json',
            'Prefer':'return=representation'
        },
        data=json.dumps(data,ensure_ascii=False).encode() if data is not None else None,
        method=method
    )
    with urllib.request.urlopen(req,timeout=15) as r:
        s=r.read().decode()
        return json.loads(s) if s else None

def cookies(h):
    result={}
    for p in (h or '').split(';'):
        if '=' in p:
            k,v=p.strip().split('=',1)
            result[k]=v
    return result

def session(h):
    token=cookies(h.headers.get('Cookie','')).get('session')
    s=sessions.get(token) if token else None

    if not s:
        return None

    if time.time()-s['created']>TTL:
        sessions.pop(token,None)
        return None

    return {'token':token,**s}

def logged(h):
    return session(h) is not None

def html_page(title,body):
    return f'''<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#080808">
<title>سامانه غدیر | {esc(title)}</title>

<style>
*{{box-sizing:border-box}}

body{{
margin:0;
min-height:100vh;
font-family:Tahoma,Arial;
color:#fff;
background:
radial-gradient(circle at 15% 10%,#493a08,transparent 30%),
radial-gradient(circle at 90% 90%,#16344a,transparent 30%),
linear-gradient(135deg,#050505,#101010 55%,#080808)
}}

.c{{
width:92%;
max-width:900px;
margin:25px auto
}}

.card{{
background:#141414ee;
border:1px solid #d4af3740;
border-radius:24px;
padding:25px;
margin-bottom:18px;
box-shadow:0 20px 60px #0008
}}

.logo{{
width:75px;
height:75px;
border-radius:22px;
margin:auto auto 15px;
display:flex;
align-items:center;
justify-content:center;
font-size:38px;
background:linear-gradient(135deg,#b8860b,#f5d76e,#8c6508)
}}

h1{{
text-align:center;
font-size:29px
}}

input,textarea,select{{
width:100%;
padding:14px;
margin:7px 0;
border-radius:14px;
border:1px solid #333;
background:#171717;
color:#fff;
font-size:16px
}}

textarea{{
min-height:180px;
line-height:1.8
}}

button,.btn{{
display:block;
width:100%;
padding:14px;
margin:9px 0;
border:0;
border-radius:14px;
text-align:center;
text-decoration:none;
font-weight:bold;
font-size:16px;
color:#111;
background:linear-gradient(135deg,#d4af37,#f5d76e);
cursor:pointer
}}

.dark{{
background:#292929!important;
color:#fff!important;
border:1px solid #444!important
}}

.red{{
background:linear-gradient(135deg,#b91c1c,#ef4444)!important;
color:#fff!important
}}

.error{{
padding:17px;
border-radius:16px;
background:#3b1515;
border:1px solid #7f3030;
text-align:center;
margin-bottom:16px
}}

.success{{
padding:22px;
border-radius:18px;
background:#12351f;
border:1px solid #2f7d4a;
text-align:center
}}

.code{{
background:#080808;
border:1px solid #d4af3740;
border-radius:14px;
padding:15px;
text-align:center;
margin:15px 0;
color:#f5d76e;
font-weight:bold
}}

.report{{
background:#161616;
border:1px solid #292929;
border-radius:18px;
padding:17px;
margin:13px 0
}}

.badge{{
display:inline-block;
padding:6px 11px;
border-radius:999px;
background:#29220d;
color:#f5d76e;
font-size:13px
}}

.text{{
white-space:pre-wrap;
line-height:2;
margin:13px 0
}}

.date{{
font-size:12px;
color:#999
}}

.stats{{
display:grid;
grid-template-columns:repeat(3,1fr);
gap:10px
}}

.stat{{
background:#171717;
border:1px solid #292929;
border-radius:15px;
padding:14px;
text-align:center;
margin:8px 0
}}

.num{{
font-size:27px;
color:#f5d76e;
font-weight:bold
}}

.back{{
display:block;
text-align:center;
color:#f5d76e;
text-decoration:none;
margin-top:13px
}}

@media(max-width:650px){{
.c{{width:94%;margin:14px auto}}
.card{{padding:19px}}
.stats{{grid-template-columns:1fr}}
}}
</style>
</head>

<body>
<div class="c">
{body}
</div>
</body>
</html>'''

def home():
    return html_page(
        'خانه',
        '''
<div class="card">

<div class="logo">🛡️</div>

<h1>سامانه غدیر</h1>

<div style="text-align:center;color:#bbb;line-height:1.9">
سامانه ثبت و پیگیری گزارش‌ها
</div>

<a class="btn" href="/report">
📝 ثبت گزارش
</a>

<a class="btn" href="/track">
🔎 پیگیری گزارش
</a>

<a class="btn dark" href="/admin">
🔐 ورود مدیریت
</a>

</div>
'''
    )

def report_page(msg=''):
    error=f'<div class="error">{esc(msg)}</div>' if msg else ''

    return html_page(
        'ثبت گزارش',
        f'''
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
maxlength="{MAX}"
placeholder="متن گزارش..."
required
></textarea>

<button type="submit">
🚀 ثبت گزارش
</button>

</form>

<a class="back" href="/">
بازگشت
</a>

</div>
'''
    )

def track_page(msg=''):
    error=f'<div class="error">{esc(msg)}</div>' if msg else ''

    return html_page(
        'پیگیری',
        f'''
<div class="card">

<div class="logo">🔎</div>

<h1>پیگیری گزارش</h1>

{error}

<form method="GET" action="/track">

<input
name="code"
placeholder="مثلاً GHD-A1B2C3D4"
required
>

<button type="submit">
🔎 پیگیری
</button>

</form>

<a class="back" href="/">
بازگشت
</a>

</div>
'''
    )

def admin_login(msg=''):
    error=f'<div class="error">{esc(msg)}</div>' if msg else ''

    return html_page(
        'ورود مدیریت',
        f'''
<div class="card">

<div class="logo">🔐</div>

<h1>ورود مدیریت</h1>

{error}

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
'''
    )

def form(h):
    length=int(h.headers.get('Content-Length','0'))

    raw=h.rfile.read(length).decode(
        'utf-8',
        'replace'
    )

    return urllib.parse.parse_qs(raw)

def out(h,content,status=200,cookies_=None):
    h.send_response(status)

    h.send_header(
        'Content-Type',
        'text/html; charset=utf-8'
    )

    h.send_header(
        'Cache-Control',
        'no-store'
    )

    h.send_header(
        'X-Content-Type-Options',
        'nosniff'
    )

    h.send_header(
        'X-Frame-Options',
        'DENY'
    )

    h.send_header(
        'Referrer-Policy',
        'no-referrer'
    )

    if cookies_:
        for x in cookies_:
            h.send_header(
                'Set-Cookie',
                x
            )

    h.end_headers()

    h.wfile.write(
        content.encode('utf-8')
    )

def redir(h,loc,c=None):
    h.send_response(302)

    h.send_header(
        'Location',
        loc
    )

    if c:
        for x in c:
            h.send_header(
                'Set-Cookie',
                x
            )

    h.end_headers()

def csrf(h,f):
    s=session(h)

    v=f.get(
        'csrf',
        ['']
    )[0]

    return (
        bool(s and v)
        and
        hmac.compare_digest(
            v,
            s['csrf']
        )
    )

def admin(h,search=''):
    s=session(h)

    rows=db(
        'GET',
        '/rest/v1/reports?select=id,created_at,report,tracking_code,status&order=created_at.desc'
    ) or []

    q=search.strip().lower()

    if q:
        rows=[
            r for r in rows
            if
            q in str(
                r.get('report','')
            ).lower()
            or
            q in str(
                r.get('tracking_code','')
            ).lower()
            or
            q in str(
                r.get('status','')
            ).lower()
        ]

    total=len(rows)

    new=sum(
        r.get('status','جدید')=='جدید'
        for r in rows
    )

    checked=sum(
        r.get('status','')=='بررسی‌شده'
        for r in rows
    )

    checking=sum(
        r.get('status','')=='در حال بررسی'
        for r in rows
    )

    cards=''

    for r in rows:

        rid=str(
            r.get('id','')
        )

        st=r.get(
            'status'
        ) or 'جدید'

        code=r.get(
            'tracking_code'
        ) or 'GHD-'+rid

        cards+=f'''
<div class="report">

<span class="badge">
📌 {esc(st)}
</span>

<div class="code">
🎫 {esc(code)}
</div>

<div class="text">
{esc(r.get('report',''))}
</div>

<div class="date">
🕐 {esc(r.get('created_at',''))}
</div>

<form method="POST" action="/status">

<input
type="hidden"
name="id"
value="{esc(rid)}"
>

<input
type="hidden"
name="csrf"
value="{esc(s['csrf'])}"
>

<select name="status">

<option {'selected' if st=='جدید' else ''}>
جدید
</option>

<option {'selected' if st=='در حال بررسی' else ''}>
در حال بررسی
</option>

<option {'selected' if st=='بررسی‌شده' else ''}>
بررسی‌شده
</option>

</select>

<button type="submit">
💾 تغییر وضعیت
</button>

</form>

<form method="POST" action="/delete">

<input
type="hidden"
name="id"
value="{esc(rid)}"
>

<input
type="hidden"
name="csrf"
value="{esc(s['csrf'])}"
>

<button
class="red"
type="submit"
>
🗑️ حذف گزارش
</button>

</form>

</div>
'''

    if not cards:
        cards='''
<div class="report"
style="text-align:center;color:#aaa">
گزارشی پیدا نشد.
</div>
'''

    return html_page(
        'مدیریت',
        f'''
<div class="card">

<div class="logo">📋</div>

<h1>پنل مدیریت</h1>

<div class="stats">

<div class="stat">
<div class="num">{total}</div>
کل
</div>

<div class="stat">
<div class="num">{new}</div>
جدید
</div>

<div class="stat">
<div class="num">{checked}</div>
بررسی‌شده
</div>

</div>

<div class="stat">

<div class="num">
{checking}
</div>

در حال بررسی

</div>

<form method="GET">

<input
name="search"
value="{esc(search)}"
placeholder="جست‌وجو"
>

<button type="submit">
🔍 جست‌وجو
</button>

</form>

{cards}

<form method="POST" action="/logout">

<input
type="hidden"
name="csrf"
value="{esc(s['csrf'])}"
>

<button
class="dark"
type="submit"
>
🚪 خروج
</button>

</form>

<a class="back" href="/">
صفحه اصلی
</a>

</div>
'''
    )

class Handler(BaseHTTPRequestHandler):

    def do_GET(self):

        p=urllib.parse.urlparse(
            self.path
        )

        q=urllib.parse.parse_qs(
            p.query
        )

        try:

            if p.path=='/':
                out(
                    self,
                    home()
                )
                return

            if p.path=='/report':
                out(
                    self,
                    report_page()
                )
                return

            if p.path=='/track':

                code=q.get(
                    'code',
                    ['']
                )[0].strip()

                if not code:
                    out(
                        self,
                        track_page()
                    )
                    return

                rows=db(
                    'GET',
                    '/rest/v1/reports?select=created_at,status,tracking_code&tracking_code=eq.'
                    +
                    urllib.parse.quote(
                        code,
                        safe=''
                    )
                ) or []

                if not rows:
                    out(
                        self,
                        track_page(
                            'گزارشی با این کد پیدا نشد.'
                        )
                    )
                    return

                r=rows[0]

                out(
                    self,
                    html_page(
                        'نتیجه',
                        f'''
<div class="card">

<div class="logo">📄</div>

<h1>
نتیجه پیگیری
</h1>

<div class="code">
🎫 {esc(r.get('tracking_code',code))}
</div>

<div
style="
text-align:center;
font-size:23px;
margin:25px 0
"
>
{esc(r.get('status','جدید'))}
</div>

<div
class="date"
style="text-align:center"
>
{esc(r.get('created_at',''))}
</div>

<a
class="back"
href="/track"
>
پیگیری دوباره
</a>

</div>
'''
                    )
                )

                return

            if p.path=='/admin':

                if logged(self):

                    out(
                        self,
                        admin(
                            self,
                            q.get(
                                'search',
                                ['']
                            )[0]
                        )
                    )

                else:

                    out(
                        self,
                        admin_login()
                    )

                return

            out(
                self,
                html_page(
                    '404',
                    '<div class="card"><h2>صفحه پیدا نشد</h2></div>'
                ),
                404
            )

        except Exception as e:

            print(
                'GET ERROR:',
                repr(e)
            )

            out(
                self,
                html_page(
                    'خطا',
                    f'<div class="card"><div class="error">{esc(e)}</div></div>'
                ),
                500
            )

    def do_POST(self):

        p=urllib.parse.urlparse(
            self.path
        ).path

        f=form(self)

        try:

            if p=='/submit':

                pw=f.get(
                    'report_password',
                    ['']
                )[0]

                text=f.get(
                    'report',
                    ['']
                )[0].strip()

                if not REPORT:

                    return out(
                        self,
                        report_page(
                            'REPORT_PASSWORD در Render تنظیم نشده است.'
                        ),
                        500
                    )

                if not hmac.compare_digest(
                    pw,
                    REPORT
                ):

                    return out(
                        self,
                        report_page(
                            'رمز ثبت گزارش اشتباه است.'
                        ),
                        403
                    )

                if not text:

                    return out(
                        self,
                        report_page(
                            'متن گزارش خالی است.'
                        ),
                        400
                    )

                if len(text)>MAX:

                    return out(
                        self,
                        report_page(
                            'گزارش بیش از حد طولانی است.'
                        ),
                        400
                    )

                code='GHD-'+secrets.token_hex(4).upper()

                db(
                    'POST',
                    '/rest/v1/reports',
                    {
                        'report':text,
                        'tracking_code':code,
                        'status':'جدید'
                    }
                )

                return out(
                    self,
                    html_page(
                        'ثبت شد',
                        f'''
<div class="card">

<div class="success">

<h2>
✅ گزارش ثبت شد
</h2>

<div class="code">
🎫 کد پیگیری
<br><br>
{esc(code)}
</div>

</div>

<a
class="back"
href="/track"
>
پیگیری
</a>

</div>
'''
                    )
                )

            if p=='/login':

                ip=self.client_address[0]
                now=time.time()

                a=[
                    x
                    for x in attempts.get(
                        ip,
                        []
                    )
                    if now-x<600
                ]

                if len(a)>=5:

                    return out(
                        self,
                        admin_login(
                            'تعداد تلاش‌ها زیاد است؛ بعداً دوباره امتحان کنید.'
                        ),
                        429
                    )

                pw=f.get(
                    'password',
                    ['']
                )[0]

                if not ADMIN:

                    return out(
                        self,
                        admin_login(
                            'ADMIN_PASSWORD در Render تنظیم نشده است.'
                        ),
                        500
                    )

                if hmac.compare_digest(
                    pw,
                    ADMIN
                ):

                    t,c=(
                        secrets.token_urlsafe(32),
                        secrets.token_urlsafe(32)
                    )

                    sessions[t]={
                        'csrf':c,
                        'created':now
                    }

                    attempts.pop(
                        ip,
                        None
                    )

                    return redir(
                        self,
                        '/admin',
                        [
                            f'session={t}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={TTL}',
                            f'csrf={c}; Path=/; Secure; SameSite=Lax; Max-Age={TTL}'
                        ]
                    )

                a.append(now)
                attempts[ip]=a

                return out(
                    self,
                    admin_login(
                        'رمز مدیریت اشتباه است.'
                    ),
                    403
                )

            if not logged(self):

                return out(
                    self,
                    html_page(
                        'دسترسی',
                        '<div class="card"><div class="error">نشست معتبر نیست.</div></div>'
                    ),
                    403
                )

            if not csrf(
                self,
                f
            ):

                return out(
                    self,
                    html_page(
                        'دسترسی',
                        '<div class="card"><div class="error">درخواست نامعتبر است.</div></div>'
                    ),
                    403
                )

            if p=='/status':

                rid=f.get(
                    'id',
                    ['']
                )[0]

                st=f.get(
                    'status',
                    ['']
                )[0]

                allowed=[
                    'جدید',
                    'در حال بررسی',
                    'بررسی‌شده'
                ]

                if (
                    not rid.isdigit()
                    or st not in allowed
                ):

                    return out(
                        self,
                        html_page(
                            'خطا',
                            '<div class="card"><div class="error">اطلاعات نامعتبر است.</div></div>'
                        ),
                        400
                    )

                db(
                    'PATCH',
                    '/rest/v1/reports?id=eq.'
                    +
                    urllib.parse.quote(
                        rid,
                        safe=''
                    ),
                    {
                        'status':st
                    }
                )

                return redir(
                    self,
                    
