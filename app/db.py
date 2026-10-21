"""
Database setup and seeding for the JobBoard vulnerable lab.

NOTE: Several design choices here are intentionally insecure for teaching
purposes (e.g. MD5 password hashing, plaintext API keys). These are called
out in docs/REPORT.md. Do not copy this into real code.
"""
import hashlib
import os
import sqlite3

DB_PATH = os.path.join(os.path.dirname(__file__), "jobboard.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def md5(text: str) -> str:
    # VULN #02: MD5 is fast and unsalted -> trivial to crack / rainbow-table.
    return hashlib.md5(text.encode()).hexdigest()


def init_db():
    """Create schema and seed data. Idempotent: wipes and recreates on run."""
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    conn = get_db()
    cur = conn.cursor()

    cur.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_md5 TEXT NOT NULL,
            email TEXT,
            role TEXT NOT NULL DEFAULT 'user',
            api_key TEXT,
            bio TEXT DEFAULT ''
        );

        CREATE TABLE jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            company TEXT,
            location TEXT,
            description TEXT,
            posted_by INTEGER
        );

        CREATE TABLE applications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            job_id INTEGER NOT NULL,
            cover_letter TEXT,
            resume_file TEXT,
            status TEXT DEFAULT 'submitted'
        );
        """
    )

    # --- Seed users ---------------------------------------------------------
    users = [
        ("admin", md5("S3cr3tAdm1n!"), "admin@jobboard.local", "admin", "AK-ADMIN-9f8e7d6c", "Site administrator."),
        ("alice", md5("password123"), "alice@example.com", "user", "AK-USER-aaa111", "Frontend developer, 5 yrs."),
        ("bob", md5("hunter2"), "bob@example.com", "user", "AK-USER-bbb222", "DevOps engineer."),
    ]
    cur.executemany(
        "INSERT INTO users (username, password_md5, email, role, api_key, bio) VALUES (?,?,?,?,?,?)",
        users,
    )

    # --- Seed jobs ----------------------------------------------------------
    jobs = [
        ("Senior Python Engineer", "Acme Corp", "Remote",
         "Build and scale our backend services. Flask/Django experience required.", 1),
        ("Security Analyst", "Globex", "New York, NY",
         "Monitor, detect, and respond to threats across our estate.", 1),
        ("Frontend Developer", "Initech", "Austin, TX",
         "React, TypeScript, and a good eye for UX.", 1),
    ]
    cur.executemany(
        "INSERT INTO jobs (title, company, location, description, posted_by) VALUES (?,?,?,?,?)",
        jobs,
    )

    # --- Seed applications (used to demonstrate IDOR) -----------------------
    apps = [
        (2, 1, "I am a great fit for this Python role.", "alice_resume.txt", "submitted"),
        (2, 3, "I love frontend work.", "alice_resume.txt", "reviewed"),
        (3, 2, "Security is my passion.", "bob_resume.txt", "submitted"),
    ]
    cur.executemany(
        "INSERT INTO applications (user_id, job_id, cover_letter, resume_file, status) VALUES (?,?,?,?,?)",
        apps,
    )

    conn.commit()
    conn.close()

    # --- Seed resume files (path-traversal / file-read targets) -------------
    uploads = os.path.join(os.path.dirname(__file__), "uploads")
    os.makedirs(uploads, exist_ok=True)
    with open(os.path.join(uploads, "alice_resume.txt"), "w", encoding="utf-8") as f:
        f.write("Alice Example\nFrontend Developer\nSkills: React, TS, CSS\n")
    with open(os.path.join(uploads, "bob_resume.txt"), "w", encoding="utf-8") as f:
        f.write("Bob Example\nDevOps Engineer\nSkills: AWS, Terraform, K8s\n")

    # A sensitive file outside the uploads dir, to prove path traversal impact.
    secret = os.path.join(os.path.dirname(__file__), "FLAG_secret_config.txt")
    with open(secret, "w", encoding="utf-8") as f:
        f.write("INTERNAL ONLY\nDB_PASSWORD=sup3rs3cr3t\nAPI_MASTER_KEY=AK-MASTER-000-DO-NOT-LEAK\n")


if __name__ == "__main__":
    init_db()
    print(f"Initialized database at {DB_PATH}")
