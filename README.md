# PhishAware

A small Flask and SQLite phishing-awareness training demo. It uses fictional sample messages that participants review inside the app. The app does not send emails, open links, collect passwords, or contact external systems.

## Run locally

1. Install Python 3.10 or newer.
2. In this directory, create and activate a virtual environment:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

3. Install Flask and start the app:

   ```powershell
   pip install -r requirements.txt
   py app.py
   ```

4. Open `http://127.0.0.1:5000` in your browser. Use `/admin` to view the local training summary.

SQLite data is stored in `phishaware.db` beside `app.py`. Delete that file or use **Clear demo results** to reset the demo. For a classroom demo, use nicknames rather than real identifying information.

## Before using beyond a local demo

This starter has no login or role-based access control; `/admin` and the reset action are intentionally unauthenticated for a local demo. Do not expose it to the internet or use it with real participant data until you add authentication, access controls, consent and retention policies, and appropriate deployment security. Set a strong `SECRET_KEY` outside the source code for any non-demo deployment.
