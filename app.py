"""PhishAware: awareness training with optional Google Web Risk URL lookups."""
from __future__ import annotations
import os
import hmac
import ipaddress
import json
import sqlite3
import threading
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from datetime import datetime, timezone
from pathlib import Path
from flask import Flask, Response, abort, flash, g, jsonify, redirect, render_template, request, send_file, url_for
from phishaware_detector import MAX_INPUT, analyze_text

BASE_DIR = Path(__file__).resolve().parent
DATABASE = Path(os.environ.get("PHISHAWARE_DB", BASE_DIR / "phishaware.db"))
app = Flask(__name__, template_folder=str(BASE_DIR), static_folder=None)
APP_ENV = os.environ.get("APP_ENV", "development").lower()
secret_key = os.environ.get("SECRET_KEY")
if APP_ENV == "production" and not secret_key:
    raise RuntimeError("Set SECRET_KEY in the production environment.")
app.config["SECRET_KEY"] = secret_key or "local-demo-change-me"
app.config["MAX_CONTENT_LENGTH"] = 30_000

WEB_RISK_API = "https://webrisk.googleapis.com/v1/uris:search"
WEB_RISK_THREATS = ("SOCIAL_ENGINEERING", "MALWARE", "UNWANTED_SOFTWARE")
MAX_LIVE_LOOKUPS = 5
_scan_requests = defaultdict(deque)
_scan_lock = threading.Lock()

def _check_web_risk(url, api_key):
    params = [("threatTypes", threat) for threat in WEB_RISK_THREATS]
    params.extend((("uri", url), ("key", api_key)))
    req = Request(f"{WEB_RISK_API}?{urlencode(params)}", headers={"Accept": "application/json", "User-Agent": "PhishAware/1.0"})
    try:
        with urlopen(req, timeout=4) as response:
            payload = json.loads(response.read(32768).decode("utf-8"))
        threats = (payload.get("threat") or {}).get("threatTypes", [])
        return {"status": "match" if threats else "no_match", "provider": "Google Web Risk", "threat_types": threats}
    except HTTPError as exc:
        return {"status": "unavailable", "provider": "Google Web Risk", "threat_types": [], "error_code": exc.code}
    except (TimeoutError, URLError, ValueError, UnicodeDecodeError, OSError):
        return {"status": "unavailable", "provider": "Google Web Risk", "threat_types": []}

def _rate_limit_scan(client):
    now = time.monotonic()
    with _scan_lock:
        bucket = _scan_requests[client]
        while bucket and now - bucket[0] >= 60:
            bucket.popleft()
        if len(bucket) >= 10:
            return False
        bucket.append(now)
        if len(_scan_requests) > 10000:
            for key in [key for key, hits in _scan_requests.items() if not hits or now - hits[-1] >= 60]:
                _scan_requests.pop(key, None)
        return True

@app.before_request
def protect_admin_pages():
    if request.endpoint not in {"admin", "reset_results"}:
        return None
    admin_password = os.environ.get("ADMIN_PASSWORD")
    if APP_ENV == "production" and not admin_password:
        abort(503, description="Admin access is disabled until ADMIN_PASSWORD is configured.")
    if not admin_password:
        return None
    credentials = request.authorization
    if credentials and hmac.compare_digest(credentials.password or "", admin_password):
        return None
    return Response("Authentication required", 401, {"WWW-Authenticate": 'Basic realm="PhishAware admin"'})

@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    return response

SCENARIOS = [
    {"id": 1, "sender": "Parcel Updates <updates@parcel-example.invalid>", "subject": "Action needed: delivery address problem", "body": "We could not complete a delivery. Review the address within 2 hours to avoid return.", "clues": ["Unexpected urgency", "Generic greeting or vague context", "A request to act through an unverified message"], "answer": "suspicious", "explanation": "The time pressure and vague delivery details are warning signs. Verify deliveries through the carrier's official app or a known contact method."},
    {"id": 2, "sender": "IT Help Desk <helpdesk@company-example.invalid>", "subject": "Scheduled maintenance notice", "body": "The staff portal will be unavailable on Saturday from 10:00 to 10:30 for planned maintenance. No action is required.", "clues": ["Expected operational notice", "No request for credentials or payment", "Specific schedule and no urgent call to action"], "answer": "legitimate", "explanation": "This sample has no credential or payment request and gives a specific maintenance window. In real situations, still verify unusual notices through a trusted channel."},
    {"id": 3, "sender": "Account Security <security@signin-example.invalid>", "subject": "Your account will be closed today", "body": "We detected a problem. Reply with your username and password so we can keep your account active.", "clues": ["Threat of account closure", "Asks for a password by email", "Sender identity cannot be trusted from the display name"], "answer": "suspicious", "explanation": "Legitimate support teams should not ask you to send your password by email. Do not reply; report the message using your organization's approved process."},
]

def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_error: Exception | None = None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db() -> None:
    DATABASE.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DATABASE)
    db.execute("""CREATE TABLE IF NOT EXISTS attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        participant TEXT NOT NULL,
        scenario_id INTEGER NOT NULL,
        answer TEXT NOT NULL CHECK(answer IN ('suspicious','legitimate')),
        correct INTEGER NOT NULL CHECK(correct IN (0,1)),
        created_at TEXT NOT NULL
    )""")
    db.commit()
    db.close()

@app.route("/style.css")
def style_css():
    return send_file(BASE_DIR / "style.css", mimetype="text/css")

@app.route("/")
def index():
    return render_template("index.html", scenarios=SCENARIOS)

@app.route("/scanner")
def scanner():
    return render_template("scanner.html")

@app.post("/api/analyze")
def analyze_message():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify(error="Send a JSON object with a text field."), 400
    text = payload.get("text", "")
    if not isinstance(text, str):
        return jsonify(error="Send a text field as a string."), 400
    if len(text) > MAX_INPUT:
        return jsonify(error="Input too large. Limit is 20,000 characters."), 413
    client_ip = request.remote_addr or "unknown"
    if APP_ENV == "production":
        forwarded_ip = request.headers.get("CF-Connecting-IP", "").strip()
        try:
            client_ip = str(ipaddress.ip_address(forwarded_ip))
        except ValueError:
            pass
    if not _rate_limit_scan(client_ip):
        return jsonify(error="Scan limit reached. Please wait a minute before trying again."), 429
    report = analyze_text(text)
    if payload.get("live_lookup") is True:
        api_key = os.environ.get("GOOGLE_WEB_RISK_API_KEY")
        if not api_key:
            report["lookup"] = {"status": "not_configured", "provider": "Google Web Risk", "urls_checked": 0}
        else:
            parsed_urls = [item for item in report["urls"] if item.get("host")]
            sensitive_skipped = sum(1 for item in parsed_urls if not item.get("live_lookup_allowed", True))
            eligible = [item for item in parsed_urls if item.get("live_lookup_allowed", True)][:MAX_LIVE_LOOKUPS]
            skipped = max(0, len(parsed_urls) - sensitive_skipped - len(eligible))
            with ThreadPoolExecutor(max_workers=5) as pool:
                futures = {pool.submit(_check_web_risk, item["url"], api_key): item for item in eligible}
                for future in as_completed(futures):
                    item = futures[future]
                    try:
                        reputation = future.result()
                    except Exception:
                        reputation = {"status": "unavailable", "provider": "Google Web Risk", "threat_types": []}
                    item["reputation"] = reputation
                    if reputation["status"] == "match":
                        item["score"] = max(item.get("local_score", 0), 90)
                        item["level"] = "Listed by threat intelligence"
                        item["findings"].insert(0, {"points": 0, "title": "Threat intelligence match", "detail": "Google Web Risk lists this URL for: " + ", ".join(reputation["threat_types"]) + ". Avoid opening it."})
            statuses = {item["reputation"]["status"] for item in eligible}
            state = "completed" if statuses and statuses <= {"match", "no_match"} and not skipped else "partial" if statuses else "no_eligible_urls" if sensitive_skipped else "no_urls"
            report["lookup"] = {"status": state, "provider": "Google Web Risk", "urls_checked": sum(1 for item in eligible if item["reputation"]["status"] in {"match", "no_match"}), "urls_skipped_limit": skipped, "urls_skipped_sensitive": sensitive_skipped}
    report["score"] = max((item["score"] for item in report["urls"]), default=0)
    return jsonify(report)

@app.get("/healthz")
def health_check():
    return jsonify(status="ok")

@app.route("/exercise/<int:scenario_id>")
def exercise(scenario_id: int):
    scenario = next((s for s in SCENARIOS if s["id"] == scenario_id), None)
    if scenario is None:
        abort(404)
    return render_template("exercise.html", scenario=scenario)

@app.post("/submit/<int:scenario_id>")
def submit(scenario_id: int):
    scenario = next((s for s in SCENARIOS if s["id"] == scenario_id), None)
    if scenario is None:
        abort(404)
    participant = request.form.get("participant", "").strip()[:40]
    answer = request.form.get("answer", "")
    if not participant:
        flash("Enter a display name to save your training result.", "error")
        return redirect(url_for("exercise", scenario_id=scenario_id))
    if answer not in {"suspicious", "legitimate"}:
        flash("Choose one of the answer options.", "error")
        return redirect(url_for("exercise", scenario_id=scenario_id))
    correct = answer == scenario["answer"]
    db = get_db()
    db.execute(
        "INSERT INTO attempts (participant, scenario_id, answer, correct, created_at) VALUES (?, ?, ?, ?, ?)",
        (participant, scenario_id, answer, int(correct), datetime.now(timezone.utc).isoformat(timespec="seconds")),
    )
    db.commit()
    return render_template("result.html", scenario=scenario, correct=correct)

@app.route("/admin")
def admin():
    rows = get_db().execute(
        """SELECT participant, COUNT(*) AS attempts, SUM(correct) AS correct,
                  ROUND(100.0 * SUM(correct) / COUNT(*), 1) AS accuracy
           FROM attempts GROUP BY participant ORDER BY participant COLLATE NOCASE"""
    ).fetchall()
    total = get_db().execute("SELECT COUNT(*) FROM attempts").fetchone()[0]
    return render_template("admin.html", rows=rows, total=total)

@app.post("/admin/reset")
def reset_results():
    get_db().execute("DELETE FROM attempts")
    get_db().commit()
    flash("Demo results cleared.", "success")
    return redirect(url_for("admin"))

init_db()

if __name__ == "__main__":
    app.run(debug=APP_ENV != "production")
