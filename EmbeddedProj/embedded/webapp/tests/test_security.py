import os
import re
import subprocess
import sys
import tempfile
import time
import uuid
import importlib
from pathlib import Path

import pytest
from werkzeug.security import generate_password_hash

WEBAPP = Path(__file__).resolve().parents[1]
os.environ["DATABASE_PATH"] = str(Path(tempfile.gettempdir()) / f"secure-otp-test-import-{uuid.uuid4().hex}.sqlite3")
sys.path.insert(0, str(WEBAPP))
import app as webapp  # noqa: E402


@pytest.fixture
def client(monkeypatch):
    test_db = Path(tempfile.gettempdir()) / f"secure-otp-test-{uuid.uuid4().hex}.sqlite3"
    monkeypatch.setattr(webapp, "DB_PATH", test_db)
    monkeypatch.setattr(webapp, "email_configured", lambda: False)
    webapp.init_db()
    webapp.app.config.update(TESTING=True, SECRET_KEY="test-secret-key-for-csrf-and-sessions")
    webapp.app.config["WTF_CSRF_ENABLED"] = True
    webapp.app.test_client_class = None
    with webapp.app.test_client() as test_client:
        yield test_client


def create_user(email="lab@example.test"):
    with webapp.database() as conn:
        cur = conn.execute("INSERT INTO users(name,email,password_hash,created_at) VALUES(?,?,?,?)",
                           ("Lab User", email, generate_password_hash("correct-horse-battery"), webapp.now_iso()))
        return conn.execute("SELECT id,name,email FROM users WHERE id=?", (cur.lastrowid,)).fetchone()


def challenge_for(user, now=None):
    with webapp.app.test_request_context("/"):
        record = webapp.issue_otp(user, purpose="simulation", now=now)
        return record["id"], webapp.challenge_demo_code(record["id"])


def test_hkdf_otp_validity_and_persisted_replay_detection(client):
    user = create_user()
    challenge_id, code = challenge_for(user)
    assert len(code) == 6 and code.isdigit()
    assert webapp.verify_challenge_code(challenge_id, code)["status"] == "valid"
    assert webapp.verify_challenge_code(challenge_id, code)["status"] == "replay"
    with webapp.database() as conn:
        assert conn.execute("SELECT COUNT(*) FROM used_otp_tokens").fetchone()[0] == 1
        events = [tuple(row) for row in conn.execute("SELECT event,details FROM activity ORDER BY id")]
    assert events == [("OTP verified", "Challenge verified"),
                      ("OTP replay", "Previously consumed challenge code")]


def test_audit_events_exclude_otp_master_and_derived_keys(client):
    user = create_user("audit@example.test")
    challenge_id, code = challenge_for(user)
    challenge = webapp.load_challenge(challenge_id)
    info = b"embedded-otp-web-v1|" + challenge["email"].lower().encode() + b"|" + challenge["session_id"]
    derived_key = webapp.hkdf_sha256(webapp.MASTER_SECRET, challenge["salt"], info)
    assert webapp.verify_challenge_code(challenge_id, code)["status"] == "valid"
    assert webapp.verify_challenge_code(challenge_id, code)["status"] == "replay"
    with webapp.database() as conn:
        audit = " ".join(" ".join(row) for row in conn.execute(
            "SELECT email,event,details FROM activity").fetchall())
    assert code not in audit
    assert webapp.MASTER_SECRET.hex() not in audit
    assert derived_key.hex() not in audit


def test_expiry_invalid_code_and_challenge_isolation(client):
    first = create_user("first@example.test")
    second = create_user("second@example.test")
    now = 1_800_000_000.0
    challenge_a, code_a = challenge_for(first, now)
    challenge_b, code_b = challenge_for(second, now)
    assert webapp.verify_challenge_code(challenge_a, code_b, now=now)["status"] == "invalid"
    assert webapp.verify_challenge_code(challenge_b, code_b, now=now)["status"] == "valid"
    challenge_c, code_c = challenge_for(first, now + 10)
    assert webapp.verify_challenge_code(challenge_c, code_c, now=now + 70)["status"] == "expired"
    with webapp.database() as conn:
        assert conn.execute("SELECT COUNT(*) FROM activity WHERE event='Expired OTP'").fetchone()[0] == 1


def test_browser_post_after_countdown_expiry_is_rejected_by_server(client):
    user = create_user("expired@example.test")
    with webapp.app.test_request_context("/"):
        record = webapp.issue_otp(user, preserve_login=True, now=time.time() - webapp.STEP_SECONDS - 2)
    with client.session_transaction() as sess:
        sess["challenge_id"] = record["id"]
    page = client.get("/verify").get_data(as_text=True)
    csrf = page.split('name="csrf_token" value="', 1)[1].split('"', 1)[0]
    code = webapp.challenge_demo_code(record["id"])
    response = client.post("/verify", data={"csrf_token": csrf, "otp": code})
    assert response.status_code == 302 and response.location.endswith("/login")
    with webapp.database() as conn:
        assert conn.execute("SELECT COUNT(*) FROM activity WHERE event='Expired OTP'").fetchone()[0] == 1


def test_progressive_backoff_lockout_and_expiration(client):
    user = create_user()
    start = 1_800_001_000.0
    challenge_id, _ = challenge_for(user, start)
    at = start
    statuses = []
    for guess in ("000000", "111111", "222222"):
        outcome = webapp.verify_challenge_code(challenge_id, guess, now=at)
        statuses.append(outcome["status"])
        at += outcome.get("retry_after", 0)
    assert statuses == ["invalid", "invalid", "locked"]
    assert webapp.verify_challenge_code(challenge_id, "999999", now=at)["status"] == "blocked"
    with webapp.database() as conn:
        assert conn.execute("SELECT COUNT(*) FROM activity WHERE event='Rate limited'").fetchone()[0] == 1
    lock_until = webapp.account_protection(user["id"])["locked_until"]
    assert lock_until == pytest.approx(at + webapp.LOCKOUT_SECONDS, abs=3)
    unlocked_at = lock_until + 1
    new_challenge, valid_code = challenge_for(user, unlocked_at)
    assert webapp.verify_challenge_code(new_challenge, valid_code, now=unlocked_at)["status"] == "valid"


def test_superseded_challenge_is_invalidated(client):
    user = create_user()
    old_id, old_code = challenge_for(user)
    new_id, new_code = challenge_for(user)
    assert webapp.verify_challenge_code(old_id, old_code)["status"] == "missing"
    assert webapp.verify_challenge_code(new_id, new_code)["status"] == "valid"


def test_registration_requires_csrf_and_login_flow_records_data(client):
    home = client.get("/")
    assert home.status_code == 200 and b"Sign in" in home.data
    home = client.get("/")
    assert home.status_code == 200 and b"Sign in" in home.data
    assert client.post("/register", data={"name": "No CSRF"}).status_code == 400
    page = client.get("/register").get_data(as_text=True)
    token = page.split('name="csrf_token" value="', 1)[1].split('"', 1)[0]
    response = client.post("/register", data={"csrf_token": token, "name": "Lab User",
        "email": "flow@example.test", "password": "correct-horse-battery"})
    assert response.status_code == 302
    response = client.post("/login", data={"email": "flow@example.test", "password": "correct-horse-battery"})
    assert response.status_code == 400  # Login form POSTs require CSRF as well.
    login_page = client.get("/login").get_data(as_text=True)
    token = login_page.split('name="csrf_token" value="', 1)[1].split('"', 1)[0]
    response = client.post("/login", data={"csrf_token": token, "email": "flow@example.test",
        "password": "correct-horse-battery"})
    assert response.status_code == 302 and response.location.endswith("/verify")
    verify_page = client.get("/verify").get_data(as_text=True)
    assert "LOCAL DEMO CODE" in verify_page
    token = verify_page.split('name="csrf_token" value="', 1)[1].split('"', 1)[0]
    code = re.search(r'<strong>(\d{6})</strong>', verify_page).group(1)
    response = client.post("/verify", data={"csrf_token": token, "otp": code})
    assert response.status_code == 302 and response.location.endswith("/dashboard")
    assert client.get("/dashboard").status_code == 200
    with webapp.database() as conn:
        events = [row[0] for row in conn.execute(
            "SELECT event FROM activity WHERE email='flow@example.test' ORDER BY id")]
    assert events == ["Registration", "OTP verified", "Successful login"]
    with client.session_transaction() as sess:
        sess.clear()
        sess["admin_authenticated"] = True
    live = client.get("/admin/monitor-data").get_json()
    assert live["stats"]["successful"] == 1
    assert any(event["event"] == "Successful login" for event in live["events"])


def test_production_without_email_fails_closed(client, monkeypatch):
    create_user("production@example.test")
    monkeypatch.setattr(webapp, "DEMO_MODE", False)
    page = client.get("/login").get_data(as_text=True)
    token = page.split('name="csrf_token" value="', 1)[1].split('"', 1)[0]
    response = client.post("/login", data={"csrf_token": token,
        "email": "production@example.test", "password": "correct-horse-battery"})
    assert response.status_code == 200
    assert b"Email OTP delivery must be configured" in response.data
    with client.session_transaction() as sess:
        assert "challenge_id" not in sess


def test_monitoring_stats_and_admin_protection(client):
    user = create_user()
    webapp.log_event(user, "Failed OTP", "bad code")
    webapp.log_event(user, "OTP replay", "replayed")
    assert client.get("/admin/monitoring").status_code == 302
    with client.session_transaction() as sess:
        sess["admin_authenticated"] = True
    page = client.get("/admin/monitoring")
    assert page.status_code == 200 and b"Security overview" in page.data
    assert b"HMACShield" in page.data
    assert b"event-filter" in page.data and b"event-search" in page.data
    assert b"refreshMonitor,5000" in page.data
    response = client.get("/admin/monitor-data")
    assert response.status_code == 200
    data = response.get_json()
    assert data["stats"]["invalid_otp"] == 1
    assert data["stats"]["replay"] == 1
    assert data["stats"]["attempts"] == 2
    assert data["events"][0]["event"] == "OTP replay"


def test_hmacshield_shell_renders_for_user_and_admin_pages(client):
    login_page = client.get("/login")
    assert login_page.status_code == 200
    assert b"HMACShield" in login_page.data
    assert b"THREAT MONITORING" in login_page.data
    assert b"Authentication" in login_page.data
    user = create_user()
    with client.session_transaction() as sess:
        sess["user_id"] = user["id"]
    assert b"HMACSHIELD / PROTECTED ACCOUNT" in client.get("/dashboard").data
    assert b"Security Events" in client.get("/activity").data
    with client.session_transaction() as sess:
        sess.clear()
        sess["admin_authenticated"] = True
    assert b"Authentication records" in client.get("/admin").data
    events_page = client.get("/admin/monitoring#events")
    assert events_page.status_code == 200
    assert b"Security event explorer" in events_page.data


def test_user_and_admin_activity_charts_use_scoped_persisted_counts(client):
    first = create_user("chart-first@example.test")
    second = create_user("chart-second@example.test")
    webapp.log_event(first, "Successful login", "login record")
    webapp.log_event(first, "Logout", "logout record")
    webapp.log_event(first, "OTP verified", "OTP record")
    webapp.log_event(second, "Successful login", "other user's record")

    with client.session_transaction() as sess:
        sess["user_id"] = first["id"]
    page = client.get("/dashboard")
    assert page.status_code == 200
    assert b"data-activity-chart" in page.data and b"activity-chart.js" in page.data
    user_snapshot = client.get("/activity-counts").get_json()
    user_data = user_snapshot["events"]
    assert len(user_snapshot["days"]) == 7
    assert user_data["Successful login"]["count"] == 1
    assert user_data["Logout"]["count"] == 1
    assert user_data["OTP verified"]["count"] == 1
    assert sum(day["counts"]["Successful login"] for day in user_snapshot["days"]) == 1

    assert client.get("/admin/activity-counts").status_code == 302
    with client.session_transaction() as sess:
        sess.clear()
        sess["admin_authenticated"] = True
    admin_snapshot = client.get("/admin/activity-counts").get_json()
    admin_data = admin_snapshot["events"]
    assert admin_data["Successful login"]["count"] == 2
    assert admin_data["Logout"]["count"] == 1
    assert admin_data["OTP verified"]["count"] == 1
    admin_page = client.get("/admin").data
    assert b"data-activity-chart" in admin_page and b"activity-chart.js" in admin_page


def test_expired_admin_csrf_shows_fresh_signin_form(client):
    response = client.post("/admin", data={"csrf_token": "stale", "username": "admin", "password": "secret"})
    assert response.status_code == 302 and response.location.endswith("/admin")
    refreshed = client.get("/admin")
    assert refreshed.status_code == 200
    assert b"Your sign-in form expired. Please try again." in refreshed.data
    with client.session_transaction() as sess:
        assert not sess.get("admin_authenticated")


def test_simulation_controls_are_admin_and_local_only(client, monkeypatch):
    assert client.get("/admin/simulations").status_code == 302
    with client.session_transaction() as sess:
        sess["admin_authenticated"] = True
    client.environ_base["REMOTE_ADDR"] = "203.0.113.45"
    assert client.get("/admin/simulations").status_code == 404
    client.environ_base["REMOTE_ADDR"] = "127.0.0.1"
    monkeypatch.setattr(webapp, "DEMO_MODE", False)
    assert client.get("/admin/simulations").status_code == 404


def test_replay_simulation_uses_verifier_and_records_both_results(client):
    user = create_user()
    with client.session_transaction() as sess:
        sess["admin_authenticated"] = True
    page = client.get("/admin/simulations").get_data(as_text=True)
    token = page.split('name="csrf_token" value="', 1)[1].split('"', 1)[0]
    response = client.post("/admin/simulations", data={"csrf_token": token,
        "scenario": "replay", "user_id": str(user["id"])})
    assert response.status_code == 200
    assert b"Consumed OTP replay rejected" in response.data
    with webapp.database() as conn:
        events = [row[0] for row in conn.execute("SELECT event FROM activity ORDER BY id")]
    assert events == ["OTP verified", "OTP replay"]


def test_simulation_post_is_rejected_while_another_simulation_runs(client):
    user = create_user()
    with client.session_transaction() as sess:
        sess["admin_authenticated"] = True
    page = client.get("/admin/simulations").get_data(as_text=True)
    token = page.split('name="csrf_token" value="', 1)[1].split('"', 1)[0]
    assert webapp.SIMULATION_LOCK.acquire(blocking=False)
    try:
        response = client.post("/admin/simulations", data={"csrf_token": token,
            "scenario": "incorrect", "user_id": str(user["id"])})
    finally:
        webapp.SIMULATION_LOCK.release()
    assert response.status_code == 302 and response.location.endswith("/admin/simulations")
    with webapp.database() as conn:
        assert conn.execute("SELECT COUNT(*) FROM activity").fetchone()[0] == 0


def test_sqlite_security_state_survives_process_restart():
    database_path = Path(tempfile.gettempdir()) / f"restart-{uuid.uuid4().hex}.sqlite3"
    env = os.environ.copy()
    env.update({"APP_MODE": "demo", "DATABASE_PATH": str(database_path),
                "OTP_MASTER_SECRET": "stable-restart-master-secret-0123456789",
                "FLASK_SECRET_KEY": "stable-restart-flask-secret-0123456789",
                "PYTHONPATH": str(WEBAPP)})
    create_state = r'''
import app, json, time
with app.database() as conn:
    first=conn.execute("INSERT INTO users(name,email,password_hash,created_at) VALUES(?,?,?,?)", ("Restart User", "restart@example.test", "unused", app.now_iso())).lastrowid
    second=conn.execute("INSERT INTO users(name,email,password_hash,created_at) VALUES(?,?,?,?)", ("Locked User", "locked@example.test", "unused", app.now_iso())).lastrowid
user=app.get_user(first)
with app.app.test_request_context("/"):
    used=app.issue_otp(user, purpose="simulation")
used_code=app.challenge_demo_code(used["id"])
assert app.verify_challenge_code(used["id"], used_code)["status"] == "valid"
with app.app.test_request_context("/"):
    pending=app.issue_otp(user, purpose="simulation")
app.log_event(user, "Failed OTP", "restart persistence probe")
with app.database() as conn:
    conn.execute("INSERT INTO account_protection(user_id,locked_until,backoff_until) VALUES(?,?,?)", (second, time.time()+300, time.time()+5))
print(json.dumps({"user": first, "locked_user": second, "used": used["id"], "pending": pending["id"]}))
'''
    first_run = subprocess.run([sys.executable, "-c", create_state], env=env,
                               check=True, capture_output=True, text=True)
    state = __import__("json").loads(first_run.stdout)
    verify_after_restart = r'''
import app, json, sys
state=json.loads(sys.argv[1])
with app.database() as conn:
    assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 2
    assert conn.execute("SELECT COUNT(*) FROM activity WHERE details='restart persistence probe'").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM otp_challenges").fetchone()[0] == 2
assert app.account_protection(state["locked_user"])["locked_until"] > 0
assert app.verify_challenge_code(state["used"], app.challenge_demo_code(state["used"]))["status"] == "replay"
assert app.verify_challenge_code(state["pending"], app.challenge_demo_code(state["pending"]))["status"] == "valid"
print("restart-state-ok")
'''
    second_run = subprocess.run([sys.executable, "-c", verify_after_restart, __import__("json").dumps(state)],
                                env=env, check=True, capture_output=True, text=True)
    assert second_run.stdout.strip() == "restart-state-ok"


@pytest.mark.parametrize("scenario,expected", [
    ("incorrect", "invalid"),
    ("bruteforce", "locked"),
    ("expired", "expired"),
])
def test_each_simulation_scenario_records_server_result(client, scenario, expected):
    user = create_user()
    with client.session_transaction() as sess:
        sess["admin_authenticated"] = True
    page = client.get("/admin/simulations").get_data(as_text=True)
    token = page.split('name="csrf_token" value="', 1)[1].split('"', 1)[0]
    response = client.post("/admin/simulations", data={"csrf_token": token,
        "scenario": scenario, "user_id": str(user["id"])})
    assert response.status_code == 200
    assert f"{expected}</span>".encode() in response.data
    with webapp.database() as conn:
        assert conn.execute("SELECT COUNT(*) FROM activity").fetchone()[0] >= 1
        simulated_failures = conn.execute(
            "SELECT COUNT(*) FROM activity WHERE event='Failed OTP' AND details LIKE '%[simulation]%'").fetchone()[0]
    assert simulated_failures <= 5

