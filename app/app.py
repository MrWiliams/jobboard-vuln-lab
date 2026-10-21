"""
JobBoard — a deliberately vulnerable Flask application.

================================ WARNING ================================
This app is INTENTIONALLY insecure. Every `# VULN #NN` comment marks a
planted vulnerability that is documented and exploited in docs/REPORT.md.
Run it on localhost only. Never deploy it. Never copy these patterns.
========================================================================
"""
import os
import socket
import sqlite3
import subprocess
import urllib.request

from flask import (
    Flask,
    Response,
    g,
    redirect,
    render_template,
    render_template_string,
    request,
    session,
    url_for,
)

import db

app = Flask(__name__)

# VULN #09: Hardcoded, guessable secret key committed to source. With a known
# secret key, an attacker can forge/tamper session cookies offline.
app.secret_key = "dev-secret-key-change-me"


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(db.DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()


# ---------------------------------------------------------------------------
# VULN #10: No security headers, and we actively advertise the stack.
# A real app should set CSP, X-Frame-Options, HSTS, etc. and not leak versions.
# ---------------------------------------------------------------------------
@app.after_request
def add_headers(resp):
    resp.headers["Server"] = "JobBoard/1.0 (Flask/Werkzeug; Python 3)"
    # Note the ABSENCE of Content-Security-Policy, X-Content-Type-Options,
    # X-Frame-Options, Strict-Transport-Security — all intentional.
    return resp


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    jobs = get_db().execute("SELECT * FROM jobs ORDER BY id").fetchall()
    return render_template("index.html", jobs=jobs, user=current_user())


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        pw_md5 = db.md5(password)

        # VULN #01: Classic SQL injection — user input concatenated straight
        # into the query. Payload `admin' --` bypasses the password check;
        # `' OR '1'='1' --` logs in as the first user.
        query = (
            "SELECT * FROM users WHERE username = '%s' AND password_md5 = '%s'"
            % (username, pw_md5)
        )
        try:
            row = get_db().execute(query).fetchone()
        except sqlite3.Error as e:
            # VULN #09: verbose DB errors leak query structure to the attacker.
            return f"<pre>SQL error: {e}\nQuery was: {query}</pre>", 500

        if row:
            # VULN #02: session just stores the raw user id with no integrity
            # beyond the weak hardcoded secret key (see VULN #09).
            session["user_id"] = row["id"]
            session["role"] = row["role"]
            return redirect(url_for("dashboard"))
        error = "Invalid credentials"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/dashboard")
def dashboard():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    apps = get_db().execute(
        "SELECT a.*, j.title, j.company FROM applications a "
        "JOIN jobs j ON a.job_id = j.id WHERE a.user_id = ?",
        (user["id"],),
    ).fetchall()
    return render_template("dashboard.html", user=user, apps=apps)


@app.route("/search")
def search():
    q = request.args.get("q", "")
    # VULN #01: second SQL injection point in the search query.
    query = (
        "SELECT * FROM jobs WHERE title LIKE '%%%s%%' OR description LIKE '%%%s%%'"
        % (q, q)
    )
    try:
        jobs = get_db().execute(query).fetchall()
    except sqlite3.Error as e:
        return f"<pre>SQL error: {e}\nQuery was: {query}</pre>", 500
    # VULN #04: reflected XSS — `q` is rendered unescaped via |safe in the template.
    return render_template("search.html", jobs=jobs, q=q, user=current_user())


@app.route("/jobs/<int:job_id>")
def job_detail(job_id):
    job = get_db().execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
    if not job:
        return "Not found", 404
    return render_template("job.html", job=job, user=current_user())


@app.route("/jobs/new", methods=["GET", "POST"])
def new_job():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    if request.method == "POST":
        # VULN #04: stored XSS — description is saved as-is and later rendered
        # with |safe, so any user viewing the job executes attacker script.
        get_db().execute(
            "INSERT INTO jobs (title, company, location, description, posted_by) "
            "VALUES (?,?,?,?,?)",
            (
                request.form.get("title"),
                request.form.get("company"),
                request.form.get("location"),
                request.form.get("description"),
                user["id"],
            ),
        )
        get_db().commit()
        return redirect(url_for("index"))
    return render_template("new_job.html", user=user)


@app.route("/application/<int:app_id>")
def view_application(app_id):
    # VULN #03: IDOR / broken access control. We require *a* login but never
    # check that the application belongs to the current user, so any logged-in
    # user can read anyone's cover letter and resume by changing the id.
    if not session.get("user_id"):
        return redirect(url_for("login"))
    app_row = get_db().execute(
        "SELECT a.*, j.title FROM applications a JOIN jobs j ON a.job_id = j.id "
        "WHERE a.id = ?",
        (app_id,),
    ).fetchone()
    if not app_row:
        return "Not found", 404
    return render_template("application.html", app=app_row, user=current_user())


@app.route("/profile", methods=["GET", "POST"])
def profile():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    if request.method == "POST":
        bio = request.form.get("bio", "")
        get_db().execute("UPDATE users SET bio = ? WHERE id = ?", (bio, user["id"]))
        get_db().commit()
        return redirect(url_for("profile"))

    # VULN #05: Server-Side Template Injection -> RCE. The stored bio is
    # concatenated into a template string and rendered, so a payload like
    # {{ 7*7 }} or {{ cycler.__init__.__globals__.os.popen('id').read() }}
    # is evaluated server-side.
    bio = user["bio"] or ""
    template = (
        "{%% extends 'profile.html' %%}{%% block bio %%}%s{%% endblock %%}" % bio
    )
    return render_template_string(template, user=user)


@app.route("/resume/convert")
def resume_convert():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    # VULN #06: OS command injection. The filename is interpolated into a shell
    # command, so `alice_resume.txt; whoami` (etc.) runs arbitrary commands.
    filename = request.args.get("file", "")
    uploads = os.path.join(os.path.dirname(__file__), "uploads")
    cmd = "cat %s" % os.path.join(uploads, filename)  # "convert" = cat, for the lab
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=10)
        body = out.decode(errors="replace")
    except subprocess.CalledProcessError as e:
        body = e.output.decode(errors="replace")
    except Exception as e:  # noqa: BLE001
        body = str(e)
    return Response(body, mimetype="text/plain")


@app.route("/resume/download")
def resume_download():
    # VULN #07: path traversal. We join uploads + user-supplied name with no
    # normalization, so `../FLAG_secret_config.txt` escapes the uploads dir.
    filename = request.args.get("file", "")
    base = os.path.join(os.path.dirname(__file__), "uploads")
    path = os.path.join(base, filename)
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        return f"error: {e}", 404
    return Response(data, mimetype="application/octet-stream")


@app.route("/jobs/import")
def jobs_import():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    # VULN #08: SSRF. The server fetches any URL the user supplies, including
    # internal/metadata endpoints (e.g. http://127.0.0.1, http://169.254.169.254).
    url = request.args.get("url", "")
    if not url:
        return "provide ?url=", 400
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:  # noqa: S310
            body = resp.read(4096)
        return Response(body, mimetype="text/plain")
    except Exception as e:  # noqa: BLE001
        return f"fetch error: {e}", 502


@app.route("/health")
def health():
    return {"status": "ok", "host": socket.gethostname()}


if __name__ == "__main__":
    db.init_db()
    print("=" * 64)
    print(" JobBoard vulnerable lab — http://127.0.0.1:5000")
    print(" Intentionally insecure. Localhost only. Do not deploy.")
    print("=" * 64)
    # VULN #09: debug=True exposes the Werkzeug interactive debugger (RCE via
    # the console PIN in some configs) and full stack traces. Bind localhost
    # only so the lab is never reachable off-host.
    app.run(host="127.0.0.1", port=5000, debug=True)
