
import os
import json
import secrets
import hashlib
import hmac
import time
import urllib.request
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http import cookies
from datetime import datetime, timezone

# =========================================================
# CONFIG
# =========================================================

PORT = int(os.environ.get("PORT", "10000"))

SUPABASE_URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
SUPABASE_KEY = os.environ.get("SUPABASE_SECRET_KEY", "")

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
REPORT_PASSWORD = os.environ.get("REPORT_PASSWORD", "")

# Session lifetime: 2 hours
SESSION_TTL = 60 * 60 * 2

# Login protection
MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW = 10 * 60
LOCK_TIME = 15 * 60

# Request limits
MAX_REPORT_LENGTH = 10000
MAX_TRACKING_LENGTH = 50

# In-memory security stores
SESSIONS = {}
LOGIN_ATTEMPTS = {}

# =========================================================
# SECURITY HELPERS
# =========================================================

def now():
    return time.time()


def client_ip(handler):
    # Do not blindly trust X-Forwarded-For.
    # Render sits behind a proxy, but this remains only an
    # approximate identifier for rate limiting.
    forwarded = handler.headers.get("X-Forwarded-For", "")

    if forwarded:
        return forwarded.split(",")[0].strip()[:100]

    return handler.client_address[0]


def secure_compare(a, b):
    if not isinstance(a, str):
        a = str(a)

    if not isinstance(b, str):
        b = str(b)

    return hmac.compare_digest(
        a.encode("utf-8"),
        b.encode("utf-8")
    )


def password_ok(received, expected):
    if not received or not expected:
        return False

    return secure_compare(received, expected)


def cleanup_sessions():
    current = now()

    expired = []

    for token, session in SESSIONS.items():
        if current - session["created"] > SESSION_TTL:
            expired.append(token)

    for token in expired:
        SESSIONS.pop(token, None)


def create_session():
    cleanup_sessions()

    token = secrets.token_urlsafe(48)
    csrf = secrets.token_urlsafe(32)

    SESSIONS[token] = {
        "csrf": csrf,
        "created": now()
    }

    return token, csrf


def destroy_session(token):
    if token:
        SESSIONS.pop(token, None)


def get_cookie(handler, name):
    raw = handler.headers.get("Cookie")

    if not raw:
        return None

    jar = cookies.SimpleCookie()

    try:
        jar.load(raw)

        if name in jar:
            return jar[name].value

    except Exception:
        pass

    return None


def get_session(handler):
    cleanup_sessions()

    token = get_cookie(
        handler,
        "ghd_session"
    )

    if not token:
        return None

    session = SESSIONS.get(token)

    if not session:
        return None

    if now() - session["created"] > SESSION_TTL:
        destroy_session(token)
        return None

    return session


def is_logged_in(handler):
    return get_session(handler) is not None


def valid_csrf(handler, supplied):
    session = get_session(handler)

    if not session:
        return False

    if not supplied:
        return False

    return secure_compare(
        supplied,
        session["csrf"]
    )


# =========================================================
# RATE LIMITING
# =========================================================

def login_allowed(ip):
    current = now()

    info = LOGIN_ATTEMPTS.get(ip)

    if not info:
        return True

    if current < info["locked_until"]:
        return False

    if current - info["first_attempt"] > LOGIN_WINDOW:
        LOGIN_ATTEMPTS.pop(ip, None)
        return True

    return info["attempts"] < MAX_LOGIN_ATTEMPTS


def login_failed(ip):
    current = now()

    info = LOGIN_ATTEMPTS.get(ip)

    if not info:
        LOGIN_ATTEMPTS[ip] = {
            "attempts": 1,
            "first_attempt": current,
            "locked_until": 0
        }
        return

    if current - info["first_attempt"] > LOGIN_WINDOW:
        LOGIN_ATTEMPTS[ip] = {
            "attempts": 1,
            "first_attempt": current,
            "locked_until": 0
        }
        return

    info["attempts"] += 1

    if info["attempts"] >= MAX_LOGIN_ATTEMPTS:
        info["locked_until"] = current + LOCK_TIME


def login_success(ip):
    LOGIN_ATTEMPTS.pop(ip, None)


# =========================================================
# SUPABASE
# =========================================================

def supabase_request(method, path, data=None):

    if not SUPABASE_URL or not SUPABASE_KEY:
        print("Supabase configuration missing")
        return None

    url = SUPABASE_URL + path

    headers = {
        "apikey": SUPABASE_KEY,
        "Authorization": "Bearer " + SUPABASE_KEY,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Prefer": "return=representation"
    }

    body = None

    if data is not None:
        body = json.dumps(
            data,
            ensure_ascii=False
        ).encode("utf-8")

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

            raw = response.read().decode(
                "utf-8",
                errors="replace"
            )

            if not raw:
                return []

            try:
                return json.loads(raw)

            except Exception:
                return raw

    except Exception as e:

        print(
            "Supabase request failed:",
            type(e).__name__
        )

        return None


# =========================================================
# GENERAL HELPERS
# =========================================================

def escape(text):

    if text is None:
        return ""

    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#039;")
    )


def generate_tracking_code():

    return (
        "GHD-"
        + secrets.token_hex(5).upper()
    )


def valid_tracking_code(code):

    if not code:
        return False

    if len(code) > MAX_TRACKING_LENGTH:
        return False

    allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"

    return all(
        char in allowed
        for char in code
    )


def valid_report(report):

    if not report:
        return False

    if len(report) > MAX_REPORT_LENGTH:
        return False

    return True


# =========================================================
# SECURITY HEADERS
# =========================================================

SECURITY_HEADERS = [

    (
        "X-Content-Type-Options",
        "nosniff"
    ),

    (
        "X-Frame-Options",
        "DENY"
    ),

    (
        "Referrer-Policy",
        "no-referrer"
    ),

    (
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=()"
    ),

    (
        "Cross-Origin-Opener-Policy",
        "same-origin"
    ),

    (
        "Content-Security-Policy",
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    ),

    (
        "Strict-Transport-Security",
        "max-age=31536000; includeSubDomains"
    )
]


# =========================================================
# CSS
# =========================================================

CSS = r"""
* {
    box-sizing: border-box;
}

:root {
    --bg:#050713;
    --panel:rgba(15,21,43,.78);
    --line:rgba(255,255,255,.09);
    --text:#f7f8ff;
    --muted:#9ba4c7;
    --blue:#5b7cff;
    --purple:#a45cff;
    --cyan:#43ddff;
    --green:#34d399;
    --yellow:#fbbf24;
    --red:#fb7185;
}

html {
    scroll-behavior:smooth;
}

body {
    margin:0;
    min-height:100vh;

    font-family:
        Tahoma,
        "Segoe UI",
        Arial,
        sans-serif;

    color:var(--text);

    background:
        radial-gradient(
            circle at 10% 10%,
            rgba(91,124,255,.22),
            transparent 32%
        ),
        radial-gradient(
            circle at 90% 15%,
            rgba(164,92,255,.18),
            transparent 30%
        ),
        radial-gradient(
            circle at 50% 100%,
            rgba(67,221,255,.08),
            transparent 35%
        ),
        var(--bg);

    overflow-x:hidden;
}

body:before {
    content:"";

    position:fixed;
    inset:0;

    pointer-events:none;

    background-image:
        linear-gradient(
            rgba(255,255,255,.025) 1px,
            transparent 1px
        ),
        linear-gradient(
            90deg,
            rgba(255,255,255,.025) 1px,
            transparent 1px
        );

    background-size:45px 45px;
}

a {
    color:inherit;
    text-decoration:none;
}

button,
input,
textarea,
select {
    font:inherit;
}

button {
    cursor:pointer;
}

.container {
    width:min(1180px,calc(100% - 32px));
    margin:auto;
}

.nav {
    position:sticky;
    top:0;
    z-index:100;

    backdrop-filter:blur(22px);
    -webkit-backdrop-filter:blur(22px);

    background:rgba(5,7,19,.72);

    border-bottom:1px solid var(--line);
}

.nav-inner {
    max-width:1180px;
    margin:auto;

    padding:17px 18px;

    display:flex;
    align-items:center;
    justify-content:space-between;
}

.brand {
    display:flex;
    align-items:center;
    gap:12px;

    font-size:19px;
    font-weight:900;
}

.logo {
    width:44px;
    height:44px;

    display:grid;
    place-items:center;

    border-radius:14px;

    background:
        linear-gradient(
            135deg,
            var(--blue),
            var(--purple)
        );

    box-shadow:
        0 0 30px rgba(91,124,255,.38);
}

.logo svg {
    width:25px;
    height:25px;
}

.nav-links {
    display:flex;
    gap:6px;
}

.nav-link {
    padding:10px 13px;
    border-radius:12px;

    color:var(--muted);

    transition:.2s;
}

.nav-link:hover {
    color:white;
    background:rgba(255,255,255,.06);
}

.hero {
    min-height:640px;

    display:flex;
    align-items:center;

    padding:75px 0;
}

.hero-grid {
    display:grid;
    grid-template-columns:1.15fr .85fr;

    align-items:center;

    gap:60px;
}

.badge {
    display:inline-flex;
    align-items:center;
    gap:8px;

    padding:8px 13px;

    border:1px solid rgba(91,124,255,.3);
    border-radius:999px;

    background:rgba(91,124,255,.08);

    color:#ccd5ff;

    font-size:13px;
    font-weight:800;
}

.badge-dot {
    width:7px;
    height:7px;

    border-radius:50%;

    background:var(--cyan);

    box-shadow:
        0 0 12px var(--cyan);
}

.hero h1 {
    margin:23px 0 18px;

    font-size:clamp(48px,7vw,86px);

    line-height:.98;

    letter-spacing:-4px;
}

.gradient-text {
    background:
        linear-gradient(
            90deg,
            white,
            #9eb1ff,
            #ca8cff
        );

    -webkit-background-clip:text;
    background-clip:text;

    color:transparent;
}

.hero p {
    max-width:650px;

    color:var(--muted);

    font-size:18px;
    line-height:1.9;
}

.actions {
    display:flex;
    flex-wrap:wrap;
    gap:12px;

    margin-top:30px;
}

.btn {
    min-height:52px;

    padding:0 22px;

    border-radius:15px;

    display:inline-flex;
    align-items:center;
    justify-content:center;
    gap:8px;

    border:1px solid transparent;

    font-weight:900;

    transition:.22s;
}

.btn:hover {
    transform:translateY(-3px);
}

.btn-primary {
    color:white;

    background:
        linear-gradient(
            135deg,
            #5878ff,
            #a056ff
        );

    box-shadow:
        0 15px 40px rgba(91,124,255,.27);
}

.btn-primary:hover {
    box-shadow:
        0 18px 50px rgba(91,124,255,.42);
}

.btn-secondary {
    color:#e9ecff;

    border-color:var(--line);

    background:rgba(255,255,255,.05);
}

.hero-visual {
    min-height:420px;

    display:grid;
    place-items:center;

    position:relative;
}

.orbit {
    position:absolute;

    width:350px;
    height:350px;

    border:1px solid rgba(91,124,255,.18);

    border-radius:50%;

    animation:spin 18s linear infinite;
}

.orbit:before,
.orbit:after {
    content:"";

    position:absolute;

    width:11px;
    height:11px;

    border-radius:50%;

    background:var(--cyan);

    box-shadow:
        0 0 15px var(--cyan),
        0 0 30px var(--cyan);
}

.orbit:before {
    top:25px;
    left:50%;
}

.orbit:after {
    right:15px;
    bottom:50px;

    background:var(--purple);

    box-shadow:
        0 0 15px var(--purple),
        0 0 30px var(--purple);
}

@keyframes spin {
    to {
        transform:rotate(360deg);
    }
}

.glow-core {
    width:260px;
    height:260px;

    display:grid;
    place-items:center;

    border-radius:50%;

    background:
        radial-gradient(
            circle,
            rgba(91,124,255,.3),
            rgba(164,92,255,.08),
            transparent 70%
        );
}

.big-logo {
    width:155px;
    height:155px;

    display:grid;
    place-items:center;

    border-radius:42px;

    background:
        linear-gradient(
            145deg,
            rgba(91,124,255,.95),
            rgba(164,92,255,.9)
        );

    box-shadow:
        0 0 65px rgba(91,124,255,.4),
        0 30px 90px rgba(0,0,0,.4);

    animation:float 4s ease-in-out infinite;
}

.big-logo svg {
    width:85px;
    height:85px;
}

@keyframes float {
    0%,100% {
        transform:translateY(0);
    }

    50% {
        transform:translateY(-12px);
    }
}

.section {
    padding:70px 0;
}

.section-head {
    text-align:center;
    margin-bottom:35px;
}

.section-head h2 {
    font-size:38px;
    margin:12px 0;
}

.section-head p {
    max-width:650px;
    margin:auto;

    color:var(--muted);

    line-height:1.8;
}

.feature-grid {
    display:grid;
    grid-template-columns:repeat(3,1fr);
    gap:17px;
}

.feature {
    padding:27px;

    min-height:215px;

    border:1px solid var(--line);
    border-radius:24px;

    background:
        linear-gradient(
            145deg,
            rgba(255,255,255,.07),
            rgba(255,255,255,.025)
        );

    backdrop-filter:blur(15px);

    transition:.25s;
}

.feature:hover {
    transform:translateY(-7px);

    border-color:
        rgba(91,124,255,.35);

    box-shadow:
        0 25px 60px rgba(0,0,0,.25);
}

.feature-icon {
    width:54px;
    height:54px;

    display:grid;
    place-items:center;

    border-radius:16px;

    background:
        rgba(91,124,255,.13);

    border:1px solid rgba(91,124,255,.2);

    font-size:24px;
}

.feature h3 {
    margin:20px 0 9px;
}

.feature p {
    color:var(--muted);
    line-height:1.8;
}

.form-wrap {
    max-width:760px;
    margin:65px auto;
}

.panel {
    padding:31px;

    border:1px solid var(--line);
    border-radius:28px;

    background:
        linear-gradient(
            145deg,
            rgba(18,25,51,.9),
            rgba(8,12,27,.9)
        );

    box-shadow:
        0 30px 100px rgba(0,0,0,.28);

    backdrop-filter:blur(20px);
}

.panel-title {
    margin-bottom:25px;
}

.panel-title h2 {
    margin:17px 0 8px;

    font-size:30px;
}

.panel-title p {
    margin:0;
    color:var(--muted);
}

.field {
    margin-bottom:18px;
}

.field label {
    display:block;

    margin-bottom:8px;

    color:#e2e6ff;

    font-size:14px;
    font-weight:800;
}

.input,
.textarea,
.select {
    width:100%;

    padding:15px 16px;

    outline:none;

    color:white;

    border:1px solid rgba(255,255,255,.1);
    border-radius:14px;

    background:
        rgba(255,255,255,.045);

    transition:.2s;
}

.input:focus,
.textarea:focus,
.select:focus {
    border-color:rgba(91,124,255,.75);

    box-shadow:
        0 0 0 4px rgba(91,124,255,.09);
}

.textarea {
    min-height:180px;
    resize:vertical;
}

.submit {
    width:100%;
    border:0;
}

.track-box {
    max-width:700px;

    margin:75px auto;

    text-align:center;
}

.track-code {
    margin:25px 0;

    padding:24px;

    border:1px solid rgba(67,221,255,.2);
    border-radius:20px;

    background:
        linear-gradient(
            135deg,
            rgba(67,221,255,.07),
            rgba(91,124,255,.08)
        );

    color:#e9fcff;

    font-size:31px;
    font-weight:1000;

    letter-spacing:3px;

    overflow-wrap:anywhere;
}

.status {
    display:inline-flex;

    padding:8px 13px;

    border-radius:999px;

    font-size:13px;
    font-weight:900;
}

.status-new {
    background:rgba(91,124,255,.13);
    color:#b1c0ff;
}

.status-progress {
    background:rgba(251,191,36,.12);
    color:#fcd34d;
}

.status-done {
    background:rgba(52,211,153,.12);
    color:#6ee7b7;
}

.admin-top {
    padding:50px 0 25px;
}

.admin-top h1 {
    margin:20px 0 7px;
    font-size:40px;
}

.admin-top p {
    color:var(--muted);
}

.stats {
    display:grid;
    grid-template-columns:repeat(3,1fr);
    gap:15px;

    margin:20px 0;
}

.stat {
    padding:22px;

    border:1px solid var(--line);
    border-radius:20px;

    background:var(--panel);
}

.stat-label {
    color:var(--muted);
    font-size:13px;
}

.stat-number {
    margin-top:9px;
    font-size:35px;
    font-weight:1000;
}

.toolbar {
    display:flex;
    flex-wrap:wrap;
    gap:10px;

    margin:22px 0;
}

.toolbar .input,
.toolbar .select {
    flex:1;
    min-width:190px;
}

.report-list {
    display:grid;
    gap:15px;
}

.report {
    padding:23px;

    border:1px solid var(--line);
    border-radius:21px;

    background:rgba(15,20,39,.8);

    transition:.2s;
}

.report:hover {
    transform:translateY(-2px);

    border-color:
        rgba(91,124,255,.3);
}

.report-head {
    display:flex;
    align-items:center;
    justify-content:space-between;

    gap:15px;

    margin-bottom:15px;
}

.report-code {
    color:#aebdff;
    font-weight:1000;
}

.report-date {
    color:var(--muted);
    font-size:12px;
    margin-top:5px;
}

.report-text {
    color:#e4e8fb;

    line-height:1.9;

    white-space:pre-wrap;
    word-break:break-word;
}

.report-actions {
    display:flex;
    flex-wrap:wrap;
    gap:8px;

    margin-top:18px;
}

.small-btn {
    padding:9px 13px;

    border:1px solid var(--line);
    border-radius:11px;

    color:white;

    background:rgba(255,255,255,.05);
}

.small-btn:hover {
    background:rgba(255,255,255,.1);
}

.danger {
    color:#fda4af;
}

.login-page {
    min-height:calc(100vh - 80px);

    display:grid;
    place-items:center;

    padding:40px 0;
}

.login-box {
    width:min(440px,100%);
    text-align:center;
}

.login-logo {
    margin:0 auto 20px;
}

.footer {
    margin-top:50px;
    padding:45px 0;

    border-top:1px solid var(--line);

    color:var(--muted);

    text-align:center;
}

.fade {
    animation:fade .6s ease both;
}

@keyframes fade {
    from {
        opacity:0;
        transform:translateY(15px);
    }

    to {
        opacity:1;
        transform:translateY(0);
    }
}

@media(max-width:850px) {

    .nav-links {
        display:none;
    }

    .container {
        width:min(100% - 22px,650px);
    }

    .hero {
        padding:60px 0 30px;
    }

    .hero-grid {
        grid-template-columns:1fr;
        gap:10px;
    }

    .hero h1 {
        font-size:53px;
    }

    .hero p {
        font-size:16px;
    }

    .hero-visual {
        min-height:350px;
    }

    .orbit {
        width:280px;
        height:280px;
    }

    .big-logo {
        width:125px;
        height:125px;
        border-radius:34px;
    }

    .big-logo svg {
        width:68px;
        height:68px;
    }

    .feature-grid,
    .stats {
        gri
