"""
SQL Injection demo — Variant 1: Authentication Bypass
Cyber Security (IT-30001) — Web Server Security assignment

Routes:
  /vulnerable  -> login built with string-concatenated SQL (the flaw)
  /secure      -> same login rewritten with a parameterized query (the fix)

Run:
  python3 init_db.py   # creates users.db with seed users
  python3 app.py        # starts the server on http://127.0.0.1:5000

IMPORTANT: This app is intentionally vulnerable. Only ever run it on
localhost / your own machine, for coursework. Never deploy it publicly.
"""
import sqlite3
import os
from flask import Flask, request, render_template, g

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")

app = Flask(__name__)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


# ---------------------------------------------------------------------
# VULNERABLE VERSION
# ---------------------------------------------------------------------
# Root cause: the username and password supplied by the client are
# concatenated directly into the SQL string. An attacker can close out
# the intended string literal and inject their own SQL logic, changing
# the query's meaning (e.g. forcing the WHERE clause to always be true,
# or commenting out the password check entirely).
@app.route("/vulnerable", methods=["GET", "POST"])
def vulnerable_login():
    error = None
    success = None
    query_shown = None
    row = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # --- VULNERABLE CODE PATH (CWE-89) ---
        query = (
            "SELECT * FROM users WHERE username = '"
            + username
            + "' AND password = '"
            + password
            + "'"
        )
        query_shown = query  # shown on page for demo/video purposes only

        db = get_db()
        try:
            cur = db.execute(query)
            row = cur.fetchone()
        except sqlite3.OperationalError as e:
            row = None
            error = f"SQL error: {e}"

        if row:
            success = f"Logged in as '{row['username']}' (role: {row['role']})"
        elif error is None:
            error = "Invalid username or password."

    return render_template(
        "login.html", mode="vulnerable", error=error, success=success,
        query_shown=query_shown, params_shown=None,
        user=row if request.method == "POST" and row else None,
        submitted=request.method == "POST",
        injected=request.method == "POST" and any(
            "'" in request.form.get(k, "") for k in ("username", "password")
        ),
    )


# ---------------------------------------------------------------------
# MITIGATED VERSION
# ---------------------------------------------------------------------
# Fix implemented: parameterized query (prepared statement). The DB
# driver sends the SQL text and the user-supplied values separately,
# so injected SQL metacharacters are treated as inert data, never as
# part of the query structure.
@app.route("/secure", methods=["GET", "POST"])
def secure_login():
    error = None
    success = None
    row = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # --- MITIGATED CODE PATH ---
        query = "SELECT * FROM users WHERE username = ? AND password = ?"
        db = get_db()
        cur = db.execute(query, (username, password))
        row = cur.fetchone()

        if row:
            success = f"Logged in as '{row['username']}' (role: {row['role']})"
        else:
            error = "Invalid username or password."

    return render_template(
        "login.html", mode="secure", error=error, success=success,
        query_shown=query if request.method == "POST" else None,
        params_shown=(username, password) if request.method == "POST" else None,
        user=row if request.method == "POST" and row else None,
        submitted=request.method == "POST",
    )


@app.route("/")
def index():
    return render_template("index.html")


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        print("users.db not found — run `python3 init_db.py` first.")
    app.run(debug=False, host="127.0.0.1", port=5000)
