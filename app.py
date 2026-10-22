"""PhishAware: a local, in-app phishing awareness training demo.

Exercises are fictional and stay inside this application. No email is sent,
no external links are loaded, and no credentials are collected.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, abort, flash, g, redirect, render_template, request, url_for

BASE_DIR = Path(__file__).resolve().parent
DATABASE = Path(os.environ.get("PHISHAWARE_DB", BASE_DIR / "phishaware.db"))
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "local-demo-change-me")

SCENARIOS = [
    {
        "id": 1,
        "sender": "Parcel Updates <updates@parcel-example.invalid>",
        "subject": "Action needed: delivery address problem",
        "body": "We could not complete a delivery. Review the address within 2 hours to avoid return.",
        "clues": ["Unexpected urgency", "Generic greeting or vague context", "A request to act through an unverified message"],
        "answer": "suspicious",
        "explanation": "The time pressure and vague delivery details are warning signs. Verify deliveries through the carrier's official app or a known contact method.",
    },
    {
        "id": 2,
        "sender": "IT Help Desk <helpdesk@company-example.invalid>",
        "subject": "Scheduled maintenance notice",
        "body": "The staff portal will be unavailable on Saturday from 10:00 to 10:30 for planned maintenance. No action is required.",
        "clues": ["Expected operational notice", "No request for credentials or payment", "Specific schedule and no urgent call to action"],
        "answer": "legitimate",
        "explanation": "This sample has no credential or payment request and gives a specific maintenance window. In real situations, still verify unusual notices through a trusted channel.",
    },
    {
        "id": 3,
        "sender": "Account Security <security@signin-example.invalid>",
        "subject": "Your account will be closed today",
        "body": "We detected a problem. Reply with your username and password so we can keep your account active.",
        "clues": ["Threat of account closure", "Asks for a password by email", "Sender identity cannot be trusted from the display name"],
        "answer": "suspicious",
        "explanation": "Legitimate support teams should not ask you to send your password by email. Do not reply; report the message using your organization's approved process.",
    },
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


@app.route("/")
def index():
    return render_template("index.html", scenarios=SCENARIOS)


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
    # Local classroom demo convenience. In production, protect admin actions with authentication.
    get_db().execute("DELETE FROM attempts")
    get_db().commit()
    flash("Demo results cleared.", "success")
    return redirect(url_for("admin"))


init_db()

if __name__ == "__main__":
    app.run(debug=True)
