# PhishAware

A local Flask and SQLite app for phishing-awareness training and static URL/message triage. Training examples use fictional messages. The scanner analyzes pasted text locally; it does not open URLs or send text to outside services.

## Run locally

Requires Python 3.10 or newer.

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
py app.py
```

Open `http://127.0.0.1:5000` for training, `http://127.0.0.1:5000/scanner` for the URL Scanner, and `http://127.0.0.1:5000/admin` for the training summary.

## Scanner

Paste a URL or message at the URL Scanner page. PhishAware checks static indicators such as IP-address hosts, embedded URL credentials, internationalized domains, link shorteners, brand-name strings in unusual hostnames, suspicious URL wording, and urgency language.

The score is a heuristic triage aid, not a probability or a verdict. A low score does not prove safety, and a high score does not prove fraud. The scanner does not resolve DNS, follow redirects, inspect web pages, download files, or use live threat-intelligence feeds. Scanner input is processed in memory and is not saved in the training database.

## Data and safe use

Training results are stored in the local `phishaware.db` database. Use nicknames for classroom exercises. Do not paste real passwords, one-time codes, or private information into the scanner.

This student prototype has no authentication or role-based access control. The `/admin` page and reset action are unauthenticated. Keep it local; do not expose it publicly or use it with real participant data until you add authentication, access controls, privacy and retention policies, and appropriate deployment security. Set a strong `SECRET_KEY` outside the source code for non-demo deployments.
