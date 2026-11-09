# SafeLink Web — SOC-style cybersecurity dashboard

This is the web version of the SafeLink educational project. It includes a responsive SOC-inspired dashboard, login/register, URL scanner, email/message scanner, account-specific scan history, CSV export, safety guide, and project information.

## Run locally on Windows

1. Install Python 3.11+ (Python 3.13/3.15 may also work if Flask wheels are available).
2. Extract this ZIP and open the `SafeLink_Website` folder in VS Code.
3. In the VS Code terminal, run:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -r requirements.txt
py app.py
```

If PowerShell blocks activation, you can skip activation and run:
```powershell
py -m pip install -r requirements.txt
py app.py
```

4. Open http://127.0.0.1:5000 in your browser.
5. Create an account on the registration page.

## Make it accessible to everyone on the internet

A local `127.0.0.1` address is accessible only from your own computer. To publish the website:
1. Create a GitHub repository and upload the contents of this folder (do not upload the database or secret keys).
2. Create a web service on a hosting platform that supports Python/Flask (for example Render).
3. Set the build/install command to `pip install -r requirements.txt`.
4. Set the start command to `gunicorn app:app`.
5. Add an environment variable `SECRET_KEY` with a long random secret. Do not use the development default.
6. Configure persistent storage and set `DATABASE_PATH` to a file on that persistent disk, or use a managed database. Without persistent storage, a SQLite database on some hosts may be erased on redeploy/restart.
7. Use HTTPS and test registration, login, logout, scans, and per-user history after deployment.

Hosting provider dashboards and pricing can change. Public access requires deployment; this ZIP alone does not publish a live URL.

## Important security notes before public launch

- This is a student prototype. Analysis is rule-based and not live threat intelligence.
- A low score does not mean a link is safe. False positives and missed threats are possible.
- The scanner does not open or fetch URLs.
- User accounts use password hashing and history is scoped by user ID. For a production service, add rate limiting, CSRF protection, email verification/password reset, logging, backups, and a production database. Configure a strong `SECRET_KEY`, HTTPS, and persistent storage before inviting real users.
- Never enter passwords, OTPs, card details, or confidential content into scans.
