"""Secure OTP login demo built with Flask, SQLite, and HKDF/HMAC-SHA256."""
import hashlib
import hmac
import json
import os
import re
import secrets
import smtplib
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from email.message import EmailMessage
from functools import wraps
from pathlib import Path

from flask import Flask, abort, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent


def load_env():
    dotenv = BASE_DIR / ".env"
    if dotenv.exists():
        for line in dotenv.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, value = line.split("=", 1)
                os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


load_env()
APP_MODE = os.environ.get("APP_MODE", "demo").lower()
DEMO_MODE = APP_MODE in {"demo", "development"}
configured_flask_secret = os.environ.get("FLASK_SECRET_KEY", "")
configured_master_secret = os.environ.get("OTP_MASTER_SECRET", "")
if APP_MODE == "production" and (
    len(configured_master_secret.encode()) < 32 or len(configured_flask_secret) < 32
    or configured_master_secret.startswith("replace-") or configured_flask_secret.startswith("replace-")
):
    raise RuntimeError("Production requires OTP_MASTER_SECRET and FLASK_SECRET_KEY (at least 32 characters each).")
app = Flask(__name__)
app.jinja_env.filters["india_time"] = lambda value: (
    datetime.fromisoformat(value).astimezone(ZoneInfo("Asia/Kolkata")).strftime("%A, %d %B %Y at %H:%M:%S IST")
    if value else "—"
)
app.config.update(
    SECRET_KEY=configured_flask_secret or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=(APP_MODE == "production" or os.environ.get("COOKIE_SECURE", "false").lower() == "true"),
)
DB_PATH = Path(os.environ.get("DATABASE_PATH", BASE_DIR / "users.sqlite3"))
if configured_master_secret and len(configured_master_secret.encode()) < 32:
    raise RuntimeError("OTP_MASTER_SECRET must contain at least 32 bytes.")
if not configured_master_secret:
    app.logger.warning("OTP_MASTER_SECRET is unset; using a temporary random key. Set it in webapp/.env for stable custom OTP sessions.")
MASTER_SECRET = configured_master_secret.encode() if configured_master_secret else secrets.token_bytes(32)
STEP_SECONDS = 60
RESEND_SECONDS = 30
LOCKOUT_SECONDS = 300
SIMULATION_LOCK = threading.Lock()


def db_connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def database():
    conn = db_connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with database() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS activity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                email TEXT NOT NULL,
                event TEXT NOT NULL,
                details TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS activity_event_time ON activity(event, created_at);
            CREATE TABLE IF NOT EXISTS otp_challenges (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                salt BLOB NOT NULL,
                session_id BLOB NOT NULL,
                step INTEGER NOT NULL,
                issued_at REAL NOT NULL,
                resend_after REAL NOT NULL,
                purpose TEXT NOT NULL DEFAULT 'login',
                consumed INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS challenge_user ON otp_challenges(user_id, created_at);
            CREATE TABLE IF NOT EXISTS used_otp_tokens (
                fingerprint TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                used_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS account_protection (
                user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                locked_until REAL NOT NULL DEFAULT 0,
                backoff_until REAL NOT NULL DEFAULT 0
            );
        """)


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def log_activity(email, event, details="", user_id=None, at=None):
    with database() as conn:
        conn.execute("INSERT INTO activity(user_id,email,event,details,created_at) VALUES(?,?,?,?,?)",
                     (user_id, email[:254], event, details[:200],
                      datetime.fromtimestamp(at, timezone.utc).isoformat(timespec="seconds") if at is not None else now_iso()))


def log_event(user, event, details="", at=None):
    """Persist a security event without recording an OTP or secret material."""
    user_id = user["user_id"] if "user_id" in user.keys() else user["id"]
    log_activity(user["email"], event, details, user_id, at)


def get_user(user_id):
    with database() as conn:
        return conn.execute("SELECT id,name,email FROM users WHERE id=?", (user_id,)).fetchone()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Sign in to view that page.", "error")
            return redirect(url_for("login"))
        if not get_user(session["user_id"]):
            session.clear()
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("admin_authenticated"):
            flash("Administrator sign-in is required.", "error")
            return redirect(url_for("admin_panel"))
        return view(*args, **kwargs)
    return wrapped


def serialize_simulation(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if request.method != "POST":
            return view(*args, **kwargs)
        if not SIMULATION_LOCK.acquire(blocking=False):
            flash("Another local simulation is running. Please try again shortly.", "error")
            return redirect(url_for("simulations"))
        try:
            return view(*args, **kwargs)
        finally:
            SIMULATION_LOCK.release()
    return wrapped


def get_csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": get_csrf_token}


def valid_csrf():
    supplied = request.form.get("csrf_token", "")
    expected = session.get("csrf_token", "")
    return bool(supplied and expected and hmac.compare_digest(supplied, expected))


def activity_totals(user_id=None):
    """Return persisted counts for the three account activity charts."""
    events = ("Successful login", "Logout", "OTP verified")
    where = " WHERE user_id=?" if user_id is not None else ""
    params = (user_id,) if user_id is not None else ()
    with database() as conn:
        rows = conn.execute(
            f"SELECT event,COUNT(*) AS total FROM activity{where} "
            "AND event IN (?,?,?) GROUP BY event" if where else
            "SELECT event,COUNT(*) AS total FROM activity "
            "WHERE event IN (?,?,?) GROUP BY event",
            params + events,
        ).fetchall()
    totals = {event: 0 for event in events}
    totals.update({row["event"]: row["total"] for row in rows})
    maximum = max(totals.values(), default=0) or 1
    return {
        "Successful login": {"label": "Successful logins", "count": totals["Successful login"], "width": round(totals["Successful login"] / maximum * 100), "class": "login"},
        "Logout": {"label": "Sign-outs", "count": totals["Logout"], "width": round(totals["Logout"] / maximum * 100), "class": "logout"},
        "OTP verified": {"label": "OTP verifications", "count": totals["OTP verified"], "width": round(totals["OTP verified"] / maximum * 100), "class": "otp"},
    }


def activity_chart_snapshot(user_id=None):
    """Counts and seven-day IST trend from persisted, scoped audit events."""
    events = activity_totals(user_id)
    today = datetime.now(ZoneInfo("Asia/Kolkata")).date()
    days = [(today - timedelta(days=offset)).isoformat() for offset in range(6, -1, -1)]
    start = days[0]
    user_filter = " AND user_id=?" if user_id is not None else ""
    params = (start, user_id) if user_id is not None else (start,)
    with database() as conn:
        rows = conn.execute(
            "SELECT date(created_at,'+5 hours','+30 minutes') AS day,event,COUNT(*) AS total "
            "FROM activity WHERE date(created_at,'+5 hours','+30 minutes')>=? "
            f"AND event IN ('Successful login','Logout','OTP verified'){user_filter} "
            "GROUP BY day,event ORDER BY day",
            params,
        ).fetchall()
    day_counts = {day: {event: 0 for event in events} for day in days}
    for row in rows:
        if row["day"] in day_counts:
            day_counts[row["day"]][row["event"]] = row["total"]
    return {
        "events": events,
        "days": [{"date": day, "counts": day_counts[day]} for day in days],
    }


def require_csrf():
    if not valid_csrf():
        abort(400, description="The form expired. Reload the page and try again.")


@app.context_processor
def inject_navigation():
    return {"is_admin": bool(session.get("admin_authenticated")),
            "current_user": bool(session.get("user_id")),
            "demo_mode": DEMO_MODE}


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length=32) -> bytes:
    prk = hmac.new(salt or b"\0" * 32, ikm, hashlib.sha256).digest()
    output, previous = b"", b""
    for counter in range(1, 256):
        previous = hmac.new(prk, previous + info + bytes([counter]), hashlib.sha256).digest()
        output += previous
        if len(output) >= length:
            return output[:length]
    raise ValueError("HKDF output too long")


def generate_otp(username: str, salt: bytes, session_id: bytes, step: int) -> str:
    info = b"embedded-otp-web-v1|" + username.encode() + b"|" + session_id
    session_key = hkdf_sha256(MASTER_SECRET, salt, info)
    digest = hmac.new(session_key, step.to_bytes(8, "big"), hashlib.sha256).digest()
    offset = digest[-1] & 0x0F
    number = int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF
    return f"{number % 1_000_000:06d}"


def token_id(session_id: bytes, code: str, step: int) -> str:
    return hmac.new(MASTER_SECRET, session_id + code.encode() + step.to_bytes(8, "big"), hashlib.sha256).hexdigest()


def session_anchor(session_id: bytes) -> str:
    alphabet = "0123456789ABCDEFGHJKLMNPQRSTUVWXYZ"
    digest = hashlib.sha256(session_id).digest()
    return "".join(alphabet[value % len(alphabet)] for value in digest[:4])


def account_protection(user_id):
    with database() as conn:
        row = conn.execute("SELECT locked_until,backoff_until FROM account_protection WHERE user_id=?",
                           (user_id,)).fetchone()
    return dict(row) if row else {"locked_until": 0, "backoff_until": 0}


def active_failure_count(user_id, now=None):
    now = time.time() if now is None else now
    with database() as conn:
        return conn.execute("""SELECT COUNT(*) FROM activity a WHERE a.user_id=? AND a.event IN ('Failed OTP','Expired OTP')
            AND julianday(a.created_at) >= julianday(?) AND a.id > COALESCE(
              (SELECT MAX(id) FROM activity WHERE user_id=? AND event IN ('OTP verified','Successful login')),0)""",
            (user_id, datetime.fromtimestamp(now - LOCKOUT_SECONDS, timezone.utc).isoformat(timespec="seconds"), user_id)).fetchone()[0]


def email_configured() -> bool:
    return (os.environ.get("EMAIL_ENABLED", "false").lower() == "true" and
            all(os.environ.get(name) for name in ("SMTP_HOST", "SMTP_PORT", "SMTP_USERNAME", "SMTP_APP_PASSWORD", "EMAIL_FROM")))


def send_email(address: str, code: str):
    message = EmailMessage()
    message["Subject"] = "Your Secure OTP sign-in code"
    message["From"] = os.environ["EMAIL_FROM"]
    message["To"] = address
    message.set_content(f"Your Secure OTP is: {code}\n\nIt expires in 60 seconds. Do not share this code.")
    with smtplib.SMTP_SSL(os.environ["SMTP_HOST"], int(os.environ["SMTP_PORT"])) as smtp:
        smtp.login(os.environ["SMTP_USERNAME"], os.environ["SMTP_APP_PASSWORD"])
        smtp.send_message(message)


def issue_otp(user, preserve_login=False, purpose="login", now=None):
    now = time.time() if now is None else now
    salt, sid, challenge_id = secrets.token_bytes(32), secrets.token_bytes(16), uuid.uuid4().hex
    step = int(now // STEP_SECONDS)
    if email_configured() and purpose != "simulation":
        code = generate_otp(user["email"].lower(), salt, sid, step)
        send_email(user["email"], code)
    with database() as conn:
        conn.execute("UPDATE otp_challenges SET consumed=1 WHERE user_id=? AND purpose=? AND consumed=0",
                     (user["id"], purpose))
        conn.execute("""INSERT INTO otp_challenges
            (id,user_id,salt,session_id,step,issued_at,resend_after,purpose,created_at)
            VALUES(?,?,?,?,?,?,?,?,?)""",
                     (challenge_id, user["id"], salt, sid, step, now, now + RESEND_SECONDS,
                      purpose, now_iso()))
    record = {"id": challenge_id, "user_id": user["id"], "username": user["email"],
              "step": step, "issued": int(now), "anchor": session_anchor(sid),
              "delivery": "Classroom demo" if purpose == "simulation" or not email_configured() else "Email",
              "preserve_login": preserve_login, "resend_after": int(now + RESEND_SECONDS)}
    if purpose == "login":
        session.pop("otp", None)
        session["challenge_id"] = challenge_id
        session.modified = True
    return record


def render_verify(record):
    return render_template("verify.html", record=record,
                           remaining=max(0, record["resend_after"] - int(time.time())),
                           demo_code=challenge_demo_code(record["id"]) if DEMO_MODE and not email_configured() else None)


def load_challenge(challenge_id):
    if not challenge_id:
        return None
    with database() as conn:
        return conn.execute("""SELECT c.*,u.email,u.name FROM otp_challenges c JOIN users u ON u.id=c.user_id
                              WHERE c.id=?""", (challenge_id,)).fetchone()


def challenge_demo_code(challenge_id):
    challenge = load_challenge(challenge_id)
    if not challenge:
        return None
    return generate_otp(challenge["email"].lower(), challenge["salt"], challenge["session_id"], challenge["step"])


def verify_challenge_code(challenge_id, code, now=None, simulation=False):
    """Shared verification path for browser login and local attack demonstrations."""
    now = time.time() if now is None else now
    event_at = time.time() if simulation else now
    protection_now = time.time() if simulation else now
    if not isinstance(code, str) or len(code) > 6:
        code = "invalid"
    challenge = load_challenge(challenge_id)
    if not challenge:
        return {"status": "missing", "reason": "No active challenge."}
    user_id, email = challenge["user_id"], challenge["email"]
    protection = account_protection(user_id)
    if protection["locked_until"] > now:
        log_event(challenge, "Rate limited", "Attempt blocked during five-minute lockout" + (" [simulation]" if simulation else ""), event_at)
        return {"status": "blocked", "reason": "Account is locked after repeated failures."}
    if protection["backoff_until"] > now:
        remaining = max(1, int(protection["backoff_until"] - now))
        log_event(challenge, "Rate limited", "Attempt blocked by progressive retry delay" + (" [simulation]" if simulation else ""), event_at)
        return {"status": "blocked", "reason": "Progressive retry delay is active.", "retry_after": remaining}
    fp = token_id(challenge["session_id"], code, challenge["step"])
    with database() as conn:
        replay = conn.execute("SELECT 1 FROM used_otp_tokens WHERE fingerprint=?", (fp,)).fetchone()
    if replay:
        log_event(challenge, "OTP replay", "Previously consumed challenge code" + (" [simulation]" if simulation else ""), event_at)
        return {"status": "replay", "reason": "This code was already used."}
    if challenge["consumed"]:
        return {"status": "missing", "reason": "This challenge has already been invalidated."}
    if now >= challenge["issued_at"] + STEP_SECONDS:
        with database() as conn:
            conn.execute("UPDATE otp_challenges SET consumed=1 WHERE id=?", (challenge_id,))
        log_event(challenge, "Expired OTP", "Challenge expired after 60 seconds" + (" [simulation]" if simulation else ""), event_at)
        failures_count = active_failure_count(user_id, now)
        locked = failures_count >= 3
        delay = 0 if locked else min(2 ** max(0, failures_count - 1), 30)
        with database() as conn:
            conn.execute("""INSERT INTO account_protection(user_id,locked_until,backoff_until) VALUES(?,?,?)
                ON CONFLICT(user_id) DO UPDATE SET locked_until=excluded.locked_until,backoff_until=excluded.backoff_until""",
                         (user_id, protection_now + LOCKOUT_SECONDS if locked else 0, protection_now + delay))
            if locked:
                conn.execute("UPDATE otp_challenges SET consumed=1 WHERE user_id=? AND consumed=0", (user_id,))
        if locked:
            log_event(challenge, "Temporary lockout", "Three failed OTP attempts; locked five minutes" + (" [simulation]" if simulation else ""), event_at)
            return {"status": "locked", "reason": "Three failures; account locked for five minutes."}
        return {"status": "expired", "reason": "The challenge expired.", "retry_after": delay}
    expected = generate_otp(email.lower(), challenge["salt"], challenge["session_id"], challenge["step"])
    valid_format = isinstance(code, str) and len(code) == 6 and code.isdigit()
    if not (valid_format and hmac.compare_digest(code, expected)):
        log_event(challenge, "Failed OTP", "Incorrect six-digit code" + (" [simulation]" if simulation else ""), event_at)
        failures_count = active_failure_count(user_id, now)
        locked = failures_count >= 3
        delay = 0 if locked else min(2 ** max(0, failures_count - 1), 30)
        with database() as conn:
            conn.execute("""INSERT INTO account_protection(user_id,locked_until,backoff_until) VALUES(?,?,?)
                ON CONFLICT(user_id) DO UPDATE SET locked_until=excluded.locked_until,backoff_until=excluded.backoff_until""",
                         (user_id, protection_now + LOCKOUT_SECONDS if locked else 0, protection_now + delay))
            if locked:
                conn.execute("UPDATE otp_challenges SET consumed=1 WHERE user_id=? AND consumed=0", (user_id,))
        if locked:
            log_event(challenge, "Temporary lockout", "Three failed OTP attempts; locked five minutes" + (" [simulation]" if simulation else ""), event_at)
            return {"status": "locked", "reason": "Three failures; account locked for five minutes."}
        return {"status": "invalid", "reason": "Incorrect OTP.", "retry_after": delay}
    try:
        with database() as conn:
            conn.execute("INSERT INTO used_otp_tokens(fingerprint,user_id,used_at) VALUES(?,?,?)", (fp, user_id, now))
            conn.execute("UPDATE otp_challenges SET consumed=1 WHERE id=?", (challenge_id,))
            conn.execute("DELETE FROM account_protection WHERE user_id=?", (user_id,))
    except sqlite3.IntegrityError:
        log_event(challenge, "OTP replay", "Previously consumed challenge code" + (" [simulation]" if simulation else ""), event_at)
        return {"status": "replay", "reason": "This code was already used."}
    log_event(challenge, "OTP verified", "Challenge verified" + (" [simulation]" if simulation else ""), event_at)
    return {"status": "valid", "reason": "OTP accepted.", "user_id": user_id, "email": email}


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        return login()
    return render_template("login.html", email_enabled=email_configured(), demo_mode=DEMO_MODE)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        require_csrf()
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not 1 <= len(name) <= 80:
            flash("Enter a name between 1 and 80 characters.", "error")
        elif len(email) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
            flash("Enter a valid email address.", "error")
        elif len(password) < 10:
            flash("Use a password with at least 10 characters.", "error")
        else:
            try:
                with database() as conn:
                    conn.execute("INSERT INTO users(name,email,password_hash,created_at) VALUES(?,?,?,?)",
                                 (name, email, generate_password_hash(password), now_iso()))
                log_activity(email, "Registration", "Account created")
                flash("Account created. Sign in with your email and password.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("An account with that email already exists.", "error")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        require_csrf()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        with database() as conn:
            row = conn.execute("SELECT * FROM users WHERE email=? COLLATE NOCASE", (email,)).fetchone()
        protection = account_protection(row["id"]) if row else {"locked_until": 0, "backoff_until": 0}
        now = time.time()
        if protection["locked_until"] > now:
            flash("Sign-in is temporarily locked after repeated OTP failures. Try again later.", "error")
            log_activity(email or "(empty)", "Rate limited", "Password sign-in blocked by lockout", row["id"] if row else None)
        elif protection["backoff_until"] > now:
            flash("Please wait before trying to sign in again.", "error")
        else:
            if not row or not check_password_hash(row["password_hash"], password):
                log_activity(email or "(empty)", "Failed password", "Invalid email or password", row["id"] if row else None)
                flash("Invalid email or password.", "error")
            elif not email_configured() and not DEMO_MODE:
                flash("Email OTP delivery must be configured before production sign-in is enabled.", "error")
            else:
                try:
                    session.clear()
                    record = issue_otp(row, preserve_login=True)
                    flash("Your sign-in code has been emailed." if email_configured() else "Local test mode: the OTP appears below.",
                          "success" if email_configured() else "test-code")
                    return redirect(url_for("verify"))
                except Exception:
                    app.logger.exception("Email delivery failed")
                    session.clear()
                    log_activity(email, "OTP delivery failed", "Email delivery error", row["id"])
                    flash("Could not send the OTP email. Check SMTP settings and try again.", "error")
    return render_template("login.html", email_enabled=email_configured(), demo_mode=DEMO_MODE)


@app.route("/verify", methods=["GET", "POST"])
def verify():
    require_csrf() if request.method == "POST" else None
    challenge_id = session.get("challenge_id")
    challenge = load_challenge(challenge_id)
    record = None
    if challenge:
        record = {"id": challenge["id"], "user_id": challenge["user_id"], "username": challenge["email"],
                  "step": challenge["step"], "issued": challenge["issued_at"],
                  "anchor": session_anchor(challenge["session_id"]),
                  "delivery": "Classroom demo" if challenge["purpose"] == "simulation" or not email_configured() else "Email",
                  "preserve_login": challenge["purpose"] == "login",
                  "resend_after": int(challenge["resend_after"])}
    if not record:
        flash("Sign in to request an OTP first.", "error")
        return redirect(url_for("login"))
    if request.method == "POST":
        code = request.form.get("otp", "").strip()
        result = verify_challenge_code(challenge_id, code)
        if result["status"] == "valid":
            session.pop("challenge_id", None)
            if record["preserve_login"]:
                session.clear()
                session["user_id"] = result["user_id"]
                log_activity(result["email"], "Successful login", "Password and OTP verified", result["user_id"])
                return redirect(url_for("dashboard"))
            return render_template("result.html", success=True, username=result["email"])
        if result["status"] == "locked":
            session.pop("challenge_id", None)
            flash(result["reason"], "error")
            return redirect(url_for("login"))
        if result["status"] == "expired":
            session.pop("challenge_id", None)
            flash(result["reason"], "error")
            return redirect(url_for("login"))
        flash(result["reason"] + (f" Retry after {result['retry_after']} second(s)." if result.get("retry_after") else ""), "error")
    return render_verify(record)


@app.route("/resend", methods=["POST"])
def resend():
    require_csrf()
    challenge_id = session.get("challenge_id")
    challenge = load_challenge(challenge_id)
    if not challenge:
        return redirect(url_for("login"))
    remaining = int(challenge["resend_after"] - time.time())
    if remaining > 0:
        flash(f"Wait {remaining} second(s) before requesting another code.", "error")
        return redirect(url_for("verify"))
    user = get_user(challenge["user_id"])
    if not user:
        session.clear()
        return redirect(url_for("login"))
    try:
        issue_otp(user, preserve_login=challenge["purpose"] == "login")
        flash("A new OTP was emailed." if email_configured() else "Local test mode: see the code below.",
              "success" if email_configured() else "test-code")
    except Exception:
        app.logger.exception("OTP resend failed")
        flash("Could not resend the OTP email. Check SMTP configuration.", "error")
    return redirect(url_for("verify"))


@app.route("/dashboard")
@login_required
def dashboard():
    user = get_user(session["user_id"])
    with database() as conn:
        activities = conn.execute("SELECT event,details,created_at FROM activity WHERE user_id=? ORDER BY id DESC LIMIT 10",
                                  (user["id"],)).fetchall()
    return render_template("dashboard.html", user=user, activities=activities)


@app.route("/activity")
@login_required
def activity():
    user = get_user(session["user_id"])
    with database() as conn:
        events = conn.execute("SELECT event,details,created_at FROM activity WHERE user_id=? ORDER BY id DESC LIMIT 100",
                              (user["id"],)).fetchall()
    return render_template("activity.html", user=user, events=events)


def activity_counts_response(user_id=None):
    response = app.response_class(
        json.dumps(activity_chart_snapshot(user_id)), mimetype="application/json"
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/activity-counts")
@login_required
def user_activity_counts():
    return activity_counts_response(session["user_id"])


@app.route("/admin", methods=["GET", "POST"])
def admin_panel():
    if not session.get("admin_authenticated") and request.method == "POST":
        if not valid_csrf():
            # A stale browser tab or a Flask restart can invalidate the signed
            # session. Return a fresh form with a clear message instead of the
            # unstyled default 400 page; the login is still rejected.
            session.pop("csrf_token", None)
            flash("Your sign-in form expired. Please try again.", "error")
            return redirect(url_for("admin_panel"))
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        expected_user = os.environ.get("ADMIN_USERNAME", "")
        expected_hash = os.environ.get("ADMIN_PASSWORD_HASH", "")
        try:
            password_valid = bool(expected_hash) and check_password_hash(expected_hash, password)
        except (ValueError, TypeError):
            app.logger.exception("ADMIN_PASSWORD_HASH is malformed; regenerate it with Werkzeug.")
            password_valid = False
        if expected_user and expected_hash and hmac.compare_digest(username, expected_user) and password_valid:
            session.clear()
            session["admin_authenticated"] = True
            session["admin_name"] = username
            session.modified = True
            return redirect(url_for("admin_panel"))
        flash("Administrator username or password is incorrect.", "error")

    if not session.get("admin_authenticated"):
        return render_template("admin_signin.html")

    try:
        with database() as conn:
            users = conn.execute("SELECT id,name,email,created_at FROM users ORDER BY id DESC").fetchall()
            login_events = conn.execute("""
                SELECT a.email, COALESCE(u.name, a.email) AS name, a.created_at
                FROM activity a LEFT JOIN users u ON u.id=a.user_id
                WHERE a.event='Successful login'
                ORDER BY a.id DESC
            """).fetchall()
            total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            total_logins = conn.execute("SELECT COUNT(*) FROM activity WHERE event='Successful login'").fetchone()[0]
    except sqlite3.Error:
        app.logger.exception("Admin page could not read database %s", DB_PATH)
        return render_template("admin.html", db_error=True, users=[], login_events=[], total_users=0, total_logins=0), 500

    def format_ist(value):
        if not value:
            return "—"
        try:
            return datetime.fromisoformat(value).astimezone(ZoneInfo("Asia/Kolkata")).strftime("%A, %d %B %Y at %H:%M:%S IST")
        except (ValueError, TypeError):
            return value

    return render_template("admin.html", db_error=False, users=users, login_events=login_events,
                           total_users=total_users, total_logins=total_logins,
                           format_ist=format_ist, db_filename=DB_PATH.name)


@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    require_csrf()
    session.clear()
    return redirect(url_for("admin_panel"))


@app.route("/admin/activity-counts")
@admin_required
def admin_activity_counts():
    return activity_counts_response()


def monitoring_snapshot():
    now = datetime.now(timezone.utc)
    start = (now - timedelta(hours=24)).isoformat(timespec="seconds")
    with database() as conn:
        rows = conn.execute("""SELECT a.id,a.email,COALESCE(u.name,a.email) AS name,a.event,a.details,a.created_at
            FROM activity a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 100""").fetchall()
        counts = {row["event"]: row["count"] for row in conn.execute(
            "SELECT event,COUNT(*) AS count FROM activity GROUP BY event").fetchall()}
        recent = conn.execute("SELECT event,COUNT(*) AS count FROM activity WHERE created_at>=? GROUP BY event",
                              (start,)).fetchall()
        hourly = conn.execute("""SELECT strftime('%H',created_at) AS hour,event,details,COUNT(*) AS count
            FROM activity WHERE created_at>=? AND event IN
            ('Successful login','OTP verified','Failed password','Failed OTP','Expired OTP','OTP replay','Rate limited')
            GROUP BY hour,event,details ORDER BY hour""", (start,)).fetchall()
        simulated_verified = conn.execute("SELECT COUNT(*) FROM activity WHERE event='OTP verified' AND details LIKE '%[simulation]%' ").fetchone()[0]
        recent_simulated_verified = conn.execute("SELECT COUNT(*) FROM activity WHERE event='OTP verified' AND details LIKE '%[simulation]%' AND created_at>=?", (start,)).fetchone()[0]
        locked = conn.execute("""SELECT u.email,p.locked_until FROM account_protection p JOIN users u ON u.id=p.user_id
            WHERE p.locked_until>? ORDER BY p.locked_until DESC""", (time.time(),)).fetchall()
    recent_counts = {row["event"]: row["count"] for row in recent}
    success = counts.get("Successful login", 0) + simulated_verified
    failed = counts.get("Failed password", 0) + counts.get("Failed OTP", 0) + counts.get("Expired OTP", 0) + counts.get("OTP replay", 0) + counts.get("Rate limited", 0)
    recent_success = recent_counts.get("Successful login", 0) + recent_simulated_verified
    recent_failed = recent_counts.get("Failed password", 0) + recent_counts.get("Failed OTP", 0) + recent_counts.get("Expired OTP", 0) + recent_counts.get("OTP replay", 0) + recent_counts.get("Rate limited", 0)
    attempts = success + failed
    categories = {
        "Failed OTP": recent_counts.get("Failed OTP", 0),
        "Expired OTP": recent_counts.get("Expired OTP", 0),
        "Replay attacks": recent_counts.get("OTP replay", 0),
        "Rate limited": recent_counts.get("Rate limited", 0),
        "Lockouts": recent_counts.get("Temporary lockout", 0),
    }
    hours = {f"{i:02d}": {"success": 0, "failed": 0} for i in range(24)}
    for row in hourly:
        bucket = hours.get(row["hour"])
        if bucket is not None:
            if row["event"] == "Successful login" or (row["event"] == "OTP verified" and "[simulation]" in row["details"]):
                bucket["success"] += row["count"]
            else:
                bucket["failed"] += row["count"]
    return {
        "stats": {"attempts": attempts, "successful": success, "failed": failed,
                  "invalid_otp": counts.get("Failed OTP", 0), "expired": counts.get("Expired OTP", 0),
                  "replay": counts.get("OTP replay", 0), "blocked": counts.get("Rate limited", 0),
                  "locked_accounts": len(locked)},
        "categories": categories,
        "recent_outcomes": {"successful": recent_success, "failed": recent_failed},
        "hours": [{"hour": hour, **values} for hour, values in hours.items()],
        "events": [{"timestamp": row["created_at"], "username": row["name"], "event": row["event"],
                    "result": "success" if row["event"] in ("Successful login", "OTP verified") else "alert",
                    "reason": row["details"]} for row in rows],
        "locked": [{"username": row["email"], "remaining": max(0, int(row["locked_until"] - time.time()))}
                   for row in locked],
        "updated_at": now.isoformat(timespec="seconds"),
    }


@app.route("/admin/monitoring")
@admin_required
def monitoring():
    snapshot = monitoring_snapshot()
    return render_template("monitoring.html", snapshot=snapshot)


@app.route("/admin/monitor-data")
@admin_required
def monitor_data():
    response = app.response_class(json.dumps(monitoring_snapshot()), mimetype="application/json")
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/admin/simulations", methods=["GET", "POST"])
@admin_required
@serialize_simulation
def simulations():
    if not DEMO_MODE or request.remote_addr not in ("127.0.0.1", "::1", None):
        abort(404)
    with database() as conn:
        users = conn.execute("SELECT id,name,email FROM users ORDER BY name COLLATE NOCASE").fetchall()
    result = None
    if request.method == "POST":
        require_csrf()
        scenario = request.form.get("scenario", "")
        try:
            user_id = int(request.form.get("user_id", "0"))
        except ValueError:
            user_id = 0
        user = next((item for item in users if item["id"] == user_id), None)
        if scenario not in {"incorrect", "bruteforce", "replay", "expired"} or user is None:
            flash("Choose a registered local account and a valid simulation.", "error")
        else:
            protection = account_protection(user_id)
            if protection["locked_until"] > time.time() and scenario != "expired":
                flash("That local account is currently locked. Let the lockout expire before simulating it.", "error")
            else:
                rec = issue_otp(user, purpose="simulation")
                code = challenge_demo_code(rec["id"])
                if scenario == "incorrect":
                    bad_code = f"{(int(code) + 1) % 1_000_000:06d}"
                    outcome = verify_challenge_code(rec["id"], bad_code, simulation=True)
                    result = {"title": "Incorrect OTP rejected", "outcomes": [outcome], "attempted": 1}
                elif scenario == "bruteforce":
                    outcomes = []
                    simulation_now = time.time()
                    for guess in ("000000", "111111", "222222", "333333", "444444"):
                        if hmac.compare_digest(guess, code):
                            guess = f"{(int(guess) + 1) % 1_000_000:06d}"
                        outcome = verify_challenge_code(rec["id"], guess, now=simulation_now, simulation=True)
                        outcomes.append(outcome)
                        simulation_now += outcome.get("retry_after", 0)
                        if outcome["status"] in ("blocked", "locked", "valid", "replay"):
                            break
                    result = {"title": "Bounded brute-force simulation stopped by account protection",
                              "outcomes": outcomes, "attempted": len(outcomes)}
                elif scenario == "replay":
                    first = verify_challenge_code(rec["id"], code, simulation=True)
                    second = verify_challenge_code(rec["id"], code, simulation=True)
                    result = {"title": "Consumed OTP replay rejected", "outcomes": [first, second], "attempted": 2}
                else:
                    expired_at = rec["issued"] + STEP_SECONDS + 1
                    outcome = verify_challenge_code(rec["id"], code, now=expired_at, simulation=True)
                    result = {"title": "Expired OTP rejected using controlled server clock",
                              "outcomes": [outcome], "attempted": 1}
    return render_template("simulations.html", users=users, result=result, demo_mode=DEMO_MODE)


@app.route("/admin/dashboard")
def legacy_admin_dashboard_url():
    return redirect(url_for("admin_panel"))


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    require_csrf()
    user = get_user(session["user_id"])
    log_activity(user["email"], "Logout", "User signed out", user["id"])
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("login"))


@app.route("/reset", methods=["POST"])
def reset():
    require_csrf()
    challenge_id = session.pop("challenge_id", None)
    if challenge_id:
        with database() as conn:
            conn.execute("UPDATE otp_challenges SET consumed=1 WHERE id=?", (challenge_id,))
    return redirect(url_for("login"))


@app.errorhandler(500)
def internal_error(error):
    original = getattr(error, "original_exception", None)
    app.logger.error("Unhandled request failure on %s", request.path, exc_info=original or error)
    return render_template("error.html", diagnostic=None), 500


init_db()

if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "5000")),
            debug=APP_MODE != "production" and os.environ.get("FLASK_DEBUG", "false").lower() == "true")

