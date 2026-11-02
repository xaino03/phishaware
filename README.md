# PhishAware

PhishAware is a Flask phishing-awareness demo with a URL and message triage scanner. It combines explainable static checks with an optional live Google Web Risk reputation lookup. It is a triage aid, not a guarantee that a URL is safe.

## Run locally

Requires Python 3.10 or newer.

    py -m venv .venv
    .\.venv\Scripts\Activate.ps1
    pip install -r requirements.txt
    py app.py

Open http://127.0.0.1:5000 for training or http://127.0.0.1:5000/scanner for the scanner.

## Scanner and privacy

- Static checks inspect URL and message text. They do not visit websites, follow redirects, resolve DNS, or download files.
- Live lookup is optional and off by default. If a user checks the Google Web Risk option, the server sends up to five extracted URLs per scan to Google's Lookup API. The remaining message text and email addresses are not sent.
- A threat-list match is a serious warning. A missing match only means no requested list match was returned at lookup time; it is not a safety verdict. Lookup failures are shown as unknown.
- Submitted scanner text is processed in memory and is not saved in the training database. Do not paste passwords, one-time codes, or confidential information.
- Keep GOOGLE_WEB_RISK_API_KEY on the server. Never place it in HTML, JavaScript, or GitHub. Restrict the key to the Web Risk API and set quotas in Google Cloud. Google's Lookup API currently includes 100,000 calls per month at no charge; extra usage may be billed. See https://cloud.google.com/web-risk/pricing.

## Deploy to Render

Create a Render Blueprint from this repository; render.yaml configures Gunicorn, health checks, and production environment variables. Add a restricted GOOGLE_WEB_RISK_API_KEY in the Render dashboard to enable live lookup. The Blueprint generates SECRET_KEY and ADMIN_PASSWORD; keep them private. Admin access is protected with HTTP Basic authentication in production. Use HTTPS and change any generated admin password you do not control.

The in-memory rate limit is per process. Use shared rate limiting or an edge/WAF for multi-instance service. Render's free service may sleep when idle and its filesystem is ephemeral; SQLite training records may disappear after replacement. Use managed persistent storage and retention controls before using real participant data.

## Limits

Heuristic scores are indicators, not calibrated probabilities. Threat feeds can miss new threats or return false positives. Independently verify unexpected requests. Do not use this student prototype as the only protection for an organization or real users.

Training attempts are stored in phishaware.db. Use nicknames in classroom exercises.
