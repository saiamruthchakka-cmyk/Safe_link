import os
import sqlite3
import json
import csv
import io
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, Response
from werkzeug.security import generate_password_hash, check_password_hash
from safelink.analyzer import analyze_url, analyze_email

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-this-before-deploying")
DB_PATH = os.environ.get("DATABASE_PATH", os.path.join(os.path.dirname(__file__), "safelink_web.db"))

def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    with db() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )""")
        con.execute("""CREATE TABLE IF NOT EXISTS scans(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            kind TEXT NOT NULL,
            label TEXT NOT NULL,
            score INTEGER NOT NULL,
            target TEXT NOT NULL,
            input_text TEXT NOT NULL,
            findings TEXT NOT NULL,
            advice TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )""")

init_db()

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapped

def save_scan(result):
    target = result.get("domain") or result.get("input", "")[:180]
    with db() as con:
        con.execute("""INSERT INTO scans(user_id,created_at,kind,label,score,target,input_text,findings,advice)
                       VALUES(?,?,?,?,?,?,?,?,?)""",
                    (session["user_id"], datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                     result["kind"], result["label"], result["score"], target,
                     result.get("input","")[:5000], json.dumps(result["findings"]), result["advice"]))

def user_scans(limit=500):
    with db() as con:
        return con.execute("SELECT * FROM scans WHERE user_id=? ORDER BY id DESC LIMIT ?",
                           (session["user_id"], limit)).fetchall()

def stats(rows):
    return {"total":len(rows),
            "low":sum(1 for r in rows if int(r["score"]) < 30),
            "medium":sum(1 for r in rows if 30 <= int(r["score"]) < 60),
            "high":sum(1 for r in rows if int(r["score"]) >= 60)}

@app.route("/")
def index():
    return redirect(url_for("dashboard") if "user_id" in session else url_for("login"))

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        if len(username) < 3 or len(username) > 32:
            flash("Username must be between 3 and 32 characters.", "error")
        elif len(password) < 10:
            flash("Use a password with at least 10 characters.", "error")
        else:
            try:
                with db() as con:
                    cur = con.execute("INSERT INTO users(username,password_hash,created_at) VALUES(?,?,?)",
                                      (username, generate_password_hash(password), datetime.now().isoformat(timespec="seconds")))
                    session.clear()
                    session["user_id"] = cur.lastrowid
                    session["username"] = username
                return redirect(url_for("dashboard"))
            except sqlite3.IntegrityError:
                flash("That username is already taken.", "error")
    return render_template("auth.html", mode="register")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        with db() as con:
            user = con.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("dashboard"))
        flash("Incorrect username or password.", "error")
    return render_template("auth.html", mode="login")

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    rows = user_scans(1000)
    return render_template("dashboard.html", stats=stats(rows), recent=rows[:6], username=session.get("username"))

@app.route("/url-scanner", methods=["GET","POST"])
@login_required
def url_scanner():
    result = None
    if request.method == "POST":
        try:
            result = analyze_url(request.form.get("url",""))
            save_scan(result)
            flash("URL analysis completed and saved to your account history.", "success")
        except ValueError as e:
            flash(str(e), "error")
    return render_template("scanner.html", mode="url", result=result)

@app.route("/email-scanner", methods=["GET","POST"])
@login_required
def email_scanner():
    result = None
    if request.method == "POST":
        try:
            result = analyze_email(request.form.get("message",""))
            save_scan(result)
            flash("Message analysis completed and saved to your account history.", "success")
        except ValueError as e:
            flash(str(e), "error")
    return render_template("scanner.html", mode="email", result=result)

@app.route("/history")
@login_required
def history():
    return render_template("history.html", rows=user_scans())

@app.route("/history/export")
@login_required
def export_history():
    rows = user_scans()
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["Scan ID","Date and time","Type","Risk label","Score","Target"])
    for r in rows:
        writer.writerow([r["id"],r["created_at"],r["kind"],r["label"],r["score"],r["target"]])
    return Response("\\ufeff"+out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition":"attachment; filename=safelink_scan_history.csv"})

@app.route("/history/clear", methods=["POST"])
@login_required
def clear_history():
    with db() as con:
        con.execute("DELETE FROM scans WHERE user_id=?", (session["user_id"],))
    flash("Your scan history was cleared.", "success")
    return redirect(url_for("history"))

@app.route("/safety-guide")
@login_required
def safety_guide():
    return render_template("info.html", page="guide")

@app.route("/about")
@login_required
def about():
    return render_template("info.html", page="about")

if __name__ == "__main__":
    # Local development only. Use a production WSGI server when deploying publicly.
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)), debug=False)
