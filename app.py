"""
Naresh XX — App Store (Python / Flask version)

A single-file Flask rewrite of the original HTML/JS app store.
Data (apps + the one admin account) is stored persistently in a local SQLite
database instead of the browser's localStorage, so it persists
across restarts and is shared for every visitor.

SECURITY / PRODUCTION NOTES (read before deploying):
  - The Werkzeug debugger is OFF. Never turn debug=True back on for
    anything reachable outside your own machine — it lets a visitor
    run arbitrary Python on your server.
  - Admin passwords are hashed (werkzeug.security), never stored
    in plain text.
  - Set a real SECRET_KEY via environment variable before deploying.
  - HTTPS: this script can serve HTTPS directly (good for testing /
    small deployments). For a real production deployment, the more
    common pattern is to run this app over plain HTTP behind a
    reverse proxy (nginx / Caddy) that terminates HTTPS with a
    certificate from Let's Encrypt — but the built-in option below
    works fine on its own too.

Setup:
    pip install flask

Admin profile: Naresh X

Run over HTTP (local dev only):
    python app.py

Run over HTTPS with a self-signed cert (browsers will warn — fine
for local testing, NOT for the public internet):
    pip install pyopenssl
    USE_HTTPS=1 python app.py

Run over HTTPS with your own real certificate (e.g. from Let's
Encrypt / certbot):
    USE_HTTPS=1 SSL_CERT=/path/to/fullchain.pem SSL_KEY=/path/to/privkey.pem python app.py

Environment variables:
    USE_HTTPS    - "1" to serve HTTPS instead of plain HTTP.
    SSL_CERT     - path to a certificate file (used with SSL_KEY).
    SSL_KEY      - path to the matching private key file.
    HOST         - interface to bind to (default 0.0.0.0, i.e. every
                   network interface on the machine — reachable from
                   other devices, not just localhost). Set to
                   127.0.0.1 to restrict it to this machine only.
    PORT         - port to bind to (default 5000, or 5443 if HTTPS on and unset).
"""

import os
import sqlite3
import secrets
from datetime import datetime

from flask import (
    Flask, request, redirect, url_for, session,
    send_from_directory, render_template_string, flash, abort
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
DB_PATH = os.path.join(BASE_DIR, "store.db")

os.makedirs(UPLOAD_DIR, exist_ok=True)

# Only these file types can be uploaded as "app files". Adjust to taste,
# but keep this an allow-list (not a block-list) — that's the safe default.
ALLOWED_APP_EXTENSIONS = {
    "zip", "exe", "msi", "dmg", "pkg", "deb", "appimage",
    "apk", "py", "whl", "tar", "gz",
}
ALLOWED_ICON_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp", "svg"}

app = Flask(__name__)

# --- Secret key -------------------------------------------------------
# Generated fresh at every startup. Simple and requires no setup, but
# note the trade-off: sessions (i.e. admin logins) won't survive a
# server restart, since a new key invalidates old session cookies.
app.secret_key = secrets.token_hex(32)

# --- Upload size limit --------------------------------------------------
# 100 MB total request size cap, to stop someone from filling your disk
# (or the RAM buffering the upload) with a single request. Adjust as needed.
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024

# --- Session / cookie hardening -----------------------------------------
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # Marks the session cookie as HTTPS-only whenever we're actually
    # serving over HTTPS (see bottom of file).
    SESSION_COOKIE_SECURE=os.environ.get("USE_HTTPS") == "1",
)


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS apps (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            price TEXT NOT NULL,
            rating REAL NOT NULL,
            description TEXT NOT NULL,
            icon_filename TEXT,
            file_filename TEXT NOT NULL,
            file_original_name TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS admin (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS app_lock (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            password_hash TEXT NOT NULL
        )
    """)
    # Create the single admin account from environment variables.
    # Registration is intentionally disabled in the UI.
    existing_admin = conn.execute("SELECT id FROM admin WHERE id = 1").fetchone()
    admin_password = os.environ.get("ADMIN_PASSWORD")
    if not existing_admin and admin_password:
        conn.execute(
            "INSERT INTO admin (id, first_name, last_name, username, password_hash) VALUES (1, ?, ?, ?, ?)",
            (
                os.environ.get("ADMIN_FIRST_NAME", "Naresh"),
                os.environ.get("ADMIN_LAST_NAME", "X"),
                os.environ.get("ADMIN_USERNAME", "Nareshx"),
                generate_password_hash(admin_password),
            ),
        )
        conn.commit()
    conn.close()


def get_admin():
    conn = get_db()
    row = conn.execute("SELECT * FROM admin WHERE id = 1").fetchone()
    conn.close()
    return row


def get_apps(order_by_rating=False):
    conn = get_db()
    sql = "SELECT * FROM apps ORDER BY " + (
        "rating DESC" if order_by_rating else "created_at DESC"
    )
    rows = conn.execute(sql).fetchall()
    conn.close()
    return rows


def format_size(num_bytes):
    if num_bytes is None:
        return ""
    if num_bytes < 1024:
        return f"{num_bytes} B"
    if num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024:.1f} KB"
    return f"{num_bytes / (1024 * 1024):.1f} MB"


def allowed_file(filename, allowed_extensions):
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in allowed_extensions


def fixed_rating_for(app_id):
    """
    Deterministic pseudo-rating derived from the app id, so we don't
    need `random` (and don't hand out a fresh random number tied to
    nothing) — purely cosmetic, replace with real ratings if you add
    a review system later.
    """
    digest = sum(bytearray(app_id.encode("utf-8")))
    return round(3.5 + (digest % 16) / 10, 1)  # 3.5 .. 5.0


# ---------------------------------------------------------------------------
# App lock helpers
# ---------------------------------------------------------------------------

def get_lock():
    conn = get_db()
    row = conn.execute("SELECT * FROM app_lock WHERE id = 1").fetchone()
    conn.close()
    return row


def set_lock_password(password):
    conn = get_db()
    conn.execute("DELETE FROM app_lock WHERE id = 1")
    conn.execute(
        "INSERT INTO app_lock (id, password_hash) VALUES (1, ?)",
        (generate_password_hash(password),),
    )
    conn.commit()
    conn.close()


def check_lock_password(password):
    row = get_lock()
    return bool(row and check_password_hash(row["password_hash"], password))


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    lock = get_lock()
    if lock and not session.get("app_unlocked"):
        return render_template_string(LOCK_TEMPLATE)
    tab = request.args.get("tab", "apps")
    apps_rows = get_apps(order_by_rating=(tab == "top"))
    admin = get_admin()
    logged_in = bool(session.get("admin_logged_in"))
    return render_template_string(
        PAGE_TEMPLATE,
        apps=apps_rows,
        tab=tab,
        admin=admin,
        logged_in=logged_in,
        format_size=format_size,
        get_lock=get_lock,
    )


@app.route("/lock/create", methods=["POST"])
def create_lock():
    password = request.form.get("password", "")
    confirm = request.form.get("confirm_password", "")
    if len(password) < 4:
        flash("❌ Lock password must be at least 4 characters.")
        return redirect(url_for("index"))
    if password != confirm:
        flash("❌ Lock passwords do not match.")
        return redirect(url_for("index"))
    set_lock_password(password)
    session["app_unlocked"] = True
    flash("🔒 App lock created successfully.")
    return redirect(url_for("index"))


@app.route("/lock/unlock", methods=["POST"])
def unlock_app():
    password = request.form.get("password", "")
    if check_lock_password(password):
        session["app_unlocked"] = True
        return redirect(url_for("index"))
    return render_template_string(LOCK_TEMPLATE, error="❌ Wrong lock password.")


@app.route("/lock", methods=["POST"])
def lock_app():
    if get_lock():
        session.pop("app_unlocked", None)
    return redirect(url_for("index"))


@app.route("/upload", methods=["POST"])
def upload():
    # Uploading is protected by the user's own app-lock password.
    lock = get_lock()
    if lock and not session.get("upload_unlocked"):
        password = request.form.get("lock_password", "")
        if not check_lock_password(password):
            flash("❌ Wrong lock password. App was not uploaded.")
            return redirect(url_for("index"))
        session["upload_unlocked"] = True

    name = request.form.get("name", "").strip()
    category = request.form.get("category", "Tools")
    price = request.form.get("price", "").strip() or "Free"
    description = request.form.get("description", "").strip() or "My uploaded application."

    app_file = request.files.get("app_file")
    icon_file = request.files.get("icon_file")

    if not name:
        flash("Please enter an app name.")
        return redirect(url_for("index"))
    if not app_file or app_file.filename == "":
        flash("Please select an app file to upload.")
        return redirect(url_for("index"))
    if not allowed_file(app_file.filename, ALLOWED_APP_EXTENSIONS):
        flash("❌ That file type isn't allowed for app uploads.")
        return redirect(url_for("index"))
    if icon_file and icon_file.filename != "" and not allowed_file(icon_file.filename, ALLOWED_ICON_EXTENSIONS):
        flash("❌ That icon file type isn't allowed (use png/jpg/gif/webp/svg).")
        return redirect(url_for("index"))

    app_id = "app_" + secrets.token_hex(8)

    file_filename = secure_filename(f"{app_id}_{app_file.filename}")
    app_file.save(os.path.join(UPLOAD_DIR, file_filename))
    file_size = os.path.getsize(os.path.join(UPLOAD_DIR, file_filename))

    icon_filename = None
    if icon_file and icon_file.filename != "":
        icon_filename = secure_filename(f"{app_id}_icon_{icon_file.filename}")
        icon_file.save(os.path.join(UPLOAD_DIR, icon_filename))

    rating = fixed_rating_for(app_id)

    conn = get_db()
    conn.execute(
        """INSERT INTO apps
           (id, name, category, price, rating, description, icon_filename,
            file_filename, file_original_name, file_size, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (app_id, name, category, price, rating, description, icon_filename,
         file_filename, app_file.filename, file_size, datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()

    session.pop("upload_unlocked", None)
    flash("✅ App uploaded successfully!")
    return redirect(url_for("index"))


@app.route("/download/<app_id>")
def download(app_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM apps WHERE id = ?", (app_id,)).fetchone()
    conn.close()
    if not row:
        abort(404)
    return send_from_directory(
        UPLOAD_DIR, row["file_filename"], as_attachment=True,
        download_name=row["file_original_name"]
    )


@app.route("/icon/<app_id>")
def icon(app_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM apps WHERE id = ?", (app_id,)).fetchone()
    conn.close()
    if not row or not row["icon_filename"]:
        abort(404)
    return send_from_directory(UPLOAD_DIR, row["icon_filename"])


@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    session.clear()
    flash("👋 Logged out.")
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# Template (single file, keeps the same dark "Code Premium" look)
# ---------------------------------------------------------------------------

LOCK_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Zero X — Locked</title>
<style>
body{margin:0;min-height:100vh;display:grid;place-items:center;font-family:Inter,system-ui,sans-serif;color:#fff;
background:radial-gradient(circle at 15% 20%,#1e3fae88,transparent 28%),
radial-gradient(circle at 85% 20%,#8a1fc988,transparent 28%),
radial-gradient(circle at 50% 90%,#ff2d9266,transparent 35%),#0a0716;}
.box{width:min(390px,calc(100% - 36px));padding:30px;border:1px solid #5d43a8;border-radius:24px;
background:linear-gradient(145deg,#20134a,#120b2c);text-align:center;box-shadow:0 20px 60px #0008;}
.logo{width:78px;height:78px;margin:auto;display:grid;place-items:center;border-radius:22px;font-size:30px;font-weight:900;
background:linear-gradient(135deg,#00d4ff,#a855f7,#ff2d92);}
h1{font-size:28px;margin:18px 0 5px;background:linear-gradient(90deg,#00d4ff,#a855f7,#ff2d92);
-webkit-background-clip:text;color:transparent;}
p{color:#b4a9d6}.row{display:grid;gap:8px;text-align:left;margin:18px 0}
label{font-size:13px;color:#d7cff0}input{padding:13px;border-radius:11px;border:1px solid #4a3b7a;
background:#160f30;color:#fff;outline:0}button{width:100%;padding:13px;border:0;border-radius:11px;
background:linear-gradient(90deg,#00d4ff,#a855f7,#ff2d92);color:#fff;font-weight:800;cursor:pointer}
.error{color:#ff8fae;margin:10px 0}
</style>
</head>
<body>
<div class="box">
  <div class="logo">ZX</div>
  <h1>Zero X</h1>
  <p>My App Store is locked</p>
  {% if error %}<div class="error">{{ error }}</div>{% endif %}
  <form method="post" action="{{ url_for('unlock_app') }}">
    <div class="row">
      <label>My Lock Password</label>
      <input type="password" name="password" autofocus required>
    </div>
    <button type="submit">🔓 Unlock</button>
  </form>
</div>
</body>
</html>
"""

PAGE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Code Premium — My App Store</title>
<style>
:root{
  --bg:#0a0716; --border:#3a2f6b; --text:#f8fbff; --muted:#b4a9d6;
  --blue:#00d4ff; --purple:#a855f7; --pink:#ff2d92; --green:#22e59a; --yellow:#ffd60a;
}
*{box-sizing:border-box}
body{
  margin:0;font-family:Inter,system-ui,sans-serif;color:var(--text);padding-bottom:40px;
  background:radial-gradient(circle at 10% 10%,#1e3fae66,transparent 25%),
             radial-gradient(circle at 90% 20%,#8a1fc966,transparent 25%),
             radial-gradient(circle at 50% 100%,#ff2d9233,transparent 30%),var(--bg);
}
a{color:inherit}
.store-header{position:sticky;top:0;z-index:50;background:linear-gradient(180deg,#1a1338,#150f2e 90%);
  border-bottom:1px solid var(--border);padding:16px 18px;}
.header-top{display:flex;align-items:center;justify-content:space-between;gap:12px;}
.logo-brand{display:flex;align-items:center;gap:12px;}
.logo-box{width:52px;height:52px;border-radius:16px;display:grid;place-items:center;font-size:24px;
  background:linear-gradient(135deg,var(--blue),var(--purple),var(--pink));}
.logo-brand h1{font-size:19px;margin:0;}
.logo-brand h1 span{background:linear-gradient(90deg,var(--blue),var(--purple),var(--pink));
  -webkit-background-clip:text;color:transparent;}
.logo-brand p{margin:2px 0 0;color:var(--muted);font-size:13px;}
.avatar-btn{width:42px;height:42px;border-radius:50%;border:2px solid var(--blue);
  background:linear-gradient(135deg,var(--blue),var(--purple));color:#fff;font-weight:800;cursor:pointer;}
.avatar-btn.admin-active{border-color:var(--green);box-shadow:0 0 14px #22e59a88;}
.search-row{margin-top:14px;}
.search-row input{width:100%;height:44px;border:1px solid var(--border);background:#160f30;color:#fff;
  border-radius:12px;padding:0 15px;outline:0;}
.content{padding:20px 16px 10px;max-width:1100px;margin:0 auto;}
.section-title{display:flex;align-items:center;gap:8px;margin:6px 0 16px;}
.tabs{display:flex;gap:10px;margin-bottom:16px;}
.tabs a{padding:8px 14px;border-radius:10px;border:1px solid var(--border);color:var(--muted);font-size:13px;}
.tabs a.active{color:#fff;border-color:var(--blue);background:#1e1642;}
.cards-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:16px;}
.card{background:linear-gradient(145deg,#20134a,#15102f 55%,#241044);border:1px solid #5d43a8;
  border-radius:16px;padding:12px 8px;text-align:center;}
.thumb{width:82%;aspect-ratio:1/1;margin:0 auto 10px;border-radius:18px;overflow:hidden;display:grid;
  place-items:center;font-size:30px;background:radial-gradient(circle,#3a2f6b,#150f2e);}
.thumb img{width:100%;height:100%;object-fit:cover;}
.card h3{font-size:12.5px;margin:0 0 4px;min-height:32px;}
.card .rating{font-size:12px;color:var(--yellow);}
.card .filesize{font-size:10px;color:var(--muted);margin-top:3px;}
.card-actions{display:flex;gap:5px;margin-top:9px;}
.small-btn{flex:1;padding:6px 4px;border-radius:7px;border:1px solid #4a3b7a;background:#1a1338;
  color:#fff;font-size:10.5px;cursor:pointer;text-decoration:none;display:inline-block;}
.install{background:linear-gradient(90deg,var(--blue),var(--purple),var(--pink));border-color:transparent;box-shadow:0 5px 16px #8a2be633;}
.empty-store{margin-top:20px;padding:55px 20px;text-align:center;border:1px dashed #4a3b7a;
  border-radius:18px;background:linear-gradient(145deg,#160f30,#1c1030);}
.btn{border:0;border-radius:11px;padding:12px 20px;background:linear-gradient(90deg,var(--blue),var(--purple),var(--pink));
  color:#fff;font-weight:800;cursor:pointer;}
.cancel{border:1px solid #4a3b7a;background:transparent;color:#dbe4f2;border-radius:10px;padding:11px 17px;cursor:pointer;}
.modal{position:fixed;inset:0;background:#000c;display:none;place-items:center;z-index:300;padding:20px;}
.modal.show{display:grid;}
.modal-card{width:min(520px,100%);max-height:90vh;overflow:auto;background:linear-gradient(145deg,#1c1440,#120b2c);
  border:1px solid #4a3b7a;border-radius:20px;padding:22px;}
.form-row{display:grid;gap:7px;margin:13px 0;}
.form-row label{font-size:13px;color:#c9bfe8;}
.form-row input,.form-row textarea,.form-row select{width:100%;border:1px solid #4a3b7a;background:#160f30;
  color:#fff;border-radius:10px;padding:11px;outline:none;}
.form-row textarea{min-height:80px;}
.modal-actions{display:flex;justify-content:flex-end;gap:10px;margin-top:16px;flex-wrap:wrap;}
.flash{background:#1e1642;border:1px solid var(--blue);border-radius:10px;padding:12px 16px;margin:14px 0;font-size:14px;}
.fab{position:fixed;right:20px;bottom:20px;border-radius:50%;width:56px;height:56px;font-size:22px;
  background:linear-gradient(90deg,var(--blue),var(--purple));border:0;color:#fff;box-shadow:0 8px 22px #a855f755;cursor:pointer;}
@keyframes colorGlow{0%,100%{filter:hue-rotate(0deg)}50%{filter:hue-rotate(35deg)}}
.logo-box,.btn,.fab{animation:colorGlow 7s ease-in-out infinite;}
</style>
</head>
<body>

<header class="store-header">
  <div class="header-top">
    <div class="logo-brand">
      <div class="logo-box">⚡</div>
      <div>
        <h1>Naresh <span>Premium</span></h1>
        <p>{{ apps|length }} Apps</p>
      </div>
    </div>
    <button class="avatar-btn"
            title="Naresh x"
            onclick="document.getElementById('adminModal').classList.add('show')">
      N
    </button>
  </div>
  <div class="search-row">
    <input id="searchInput" type="search" placeholder="Search my apps..." oninput="filterCards()">
  </div>
</header>

<div class="content">
  {% with messages = get_flashed_messages() %}
    {% for m in messages %}<div class="flash">{{ m }}</div>{% endfor %}
  {% endwith %}

  <div class="tabs">
    <a href="{{ url_for('index', tab='apps') }}" class="{{ 'active' if tab != 'top' else '' }}">▦ Apps</a>
    <a href="{{ url_for('index', tab='top') }}" class="{{ 'active' if tab == 'top' else '' }}">🏆 Top Apps</a>
  </div>

  <div class="section-title"><h2>{{ 'Top Apps' if tab == 'top' else 'All Apps' }}</h2></div>

  {% if apps %}
  <div class="cards-grid" id="appsGrid">
    {% for a in apps %}
    <article class="card" data-name="{{ a['name']|lower }}">
      <div class="thumb">
        {% if a['icon_filename'] %}
          <img src="{{ url_for('icon', app_id=a['id']) }}" alt="{{ a['name'] }} icon">
        {% else %}
          <div style="width:100%;height:100%;display:grid;place-items:center;font-size:34px;font-weight:900;
                      background:linear-gradient(135deg,var(--blue),var(--purple),var(--pink));color:#fff;">
            {{ a['name'][0]|upper }}
          </div>
        {% endif %}
      </div>
      <h3>{{ a['name'] }}</h3>
      <div class="rating">★ {{ a['rating'] }}</div>
      <div class="filesize">{{ format_size(a['file_size']) }}</div>
      <div class="card-actions">
        <a class="small-btn install" href="{{ url_for('download', app_id=a['id']) }}">Install</a>
      </div>
    </article>
    {% endfor %}
  </div>
  {% else %}
  <div class="empty-store">
    <div style="font-size:56px;">📦</div>
    <h2>Your Store Is Empty</h2>
    <p style="color:var(--muted)">No apps have been uploaded yet.</p>
    <button class="btn" style="margin-top:14px;" onclick="document.getElementById('uploadModal').classList.add('show')">
      🚀 Upload Your First App
    </button>
  </div>
  {% endif %}
</div>

<button class="fab" title="Add app or lock" onclick="document.getElementById('plusModal').classList.add('show')">➕</button>

<!-- Plus menu -->
<div class="modal" id="plusModal">
  <div class="modal-card" style="text-align:center;">
    <h2>➕ Add</h2>
    <p style="color:var(--muted)">Choose what you want to create.</p>
    <div class="modal-actions" style="justify-content:center;">
      <button type="button" class="btn"
              onclick="document.getElementById('plusModal').classList.remove('show');document.getElementById('uploadModal').classList.add('show')">
        🚀 Upload App
      </button>
      <button type="button" class="btn"
              onclick="document.getElementById('plusModal').classList.remove('show');document.getElementById('lockModal').classList.add('show')">
        🔒 Create Lock
      </button>
    </div>
    <button type="button" class="cancel"
            onclick="document.getElementById('plusModal').classList.remove('show')">Close</button>
  </div>
</div>

<!-- Create lock modal -->
<div class="modal" id="lockModal">
  <div class="modal-card">
    <h2>🔒 Create My Lock</h2>
    <p style="color:var(--muted)">Only you choose this password. It is stored as a secure hash.</p>
    <form method="post" action="{{ url_for('create_lock') }}">
      <div class="form-row">
        <label>My Lock Password</label>
        <input type="password" name="password" minlength="4" required>
      </div>
      <div class="form-row">
        <label>Confirm Lock Password</label>
        <input type="password" name="confirm_password" minlength="4" required>
      </div>
      <div class="modal-actions">
        <button type="button" class="cancel"
                onclick="document.getElementById('lockModal').classList.remove('show')">Cancel</button>
        <button class="btn" type="submit">🔐 Create Lock</button>
      </div>
    </form>
  </div>
</div>

<!-- Upload modal -->
<div class="modal" id="uploadModal">
  <div class="modal-card">
    <h2>🚀 Upload Your App</h2><p style="color:var(--muted)">🔒 Your lock password is required to publish an app.</p>
    <form method="post" action="{{ url_for('upload') }}" enctype="multipart/form-data">
      {% if get_lock() %}
      <div class="form-row">
        <label>🔒 My Lock Password</label>
        <input type="password" name="lock_password" placeholder="Enter your lock password" required>
      </div>
      {% endif %}
      <div class="form-row"><label>App Name</label><input name="name" placeholder="My Python App" required></div>
      <div class="form-row">
        <label>Category</label>
        <select name="category">
          <option>Productivity</option><option>Design</option><option>Tools</option>
          <option>Games</option><option>Books</option><option>Utilities</option>
        </select>
      </div>
      <div class="form-row"><label>Price</label><input name="price" placeholder="Free"></div>
      <div class="form-row"><label>Icon Image (optional)</label><input type="file" name="icon_file" accept="image/*"></div>
      <div class="form-row"><label>App File (required)</label><input type="file" name="app_file" required></div>
      <div class="form-row"><label>Description</label><textarea name="description"></textarea></div>
      <div class="modal-actions">
        <button type="button" class="cancel" onclick="document.getElementById('uploadModal').classList.remove('show')">Cancel</button>
        <button class="btn" type="submit">🚀 Publish App</button>
      </div>
    </form>
  </div>
</div>

<!-- Naresh X title modal -->
<div class="modal" id="adminModal">
  <div class="modal-card" style="text-align:center;">
    <div class="logo-box" style="margin:0 auto 14px;width:72px;height:72px;font-size:30px;">NX</div>
    <h2 style="font-size:28px;margin:8px 0;
               background:linear-gradient(90deg,var(--blue),var(--purple),var(--pink));
               -webkit-background-clip:text;color:transparent;">
      Naresh X
    </h2>
    <p style="color:var(--muted);margin-bottom:22px;">My App Store</p>
    {% if get_lock is defined %}{% endif %}
    <button type="button" class="btn"
            onclick="document.getElementById('adminModal').classList.remove('show')">
      Close
    </button>
  </div>
</div>

<script>
function filterCards(){
  const q = document.getElementById('searchInput').value.toLowerCase().trim();
  document.querySelectorAll('.card').forEach(card=>{
    card.style.display = (!q || card.dataset.name.includes(q)) ? '' : 'none';
  });
}
document.querySelectorAll('.modal').forEach(m=>{
  m.addEventListener('click', e=>{ if(e.target === m) m.classList.remove('show'); });
});
</script>
</body>
</html>
"""

if __name__ == "__main__":
    init_db()

    use_https = os.environ.get("USE_HTTPS") == "1"
    # Bound to 0.0.0.0: the server listens on every network interface
    # on the machine (not just localhost), so it's reachable from
    # other devices on your network/the internet at the machine's IP.
    # That's what makes the port "open" — set HOST=127.0.0.1 instead
    # if you only want it reachable from this machine.
    host = os.environ.get("HOST", "0.0.0.0")
    default_port = 5443 if use_https else 5000
    port = int(os.environ.get("PORT", default_port))

    ssl_context = None
    if use_https:
        cert_path = os.environ.get("SSL_CERT")
        key_path = os.environ.get("SSL_KEY")
        if cert_path and key_path:
            ssl_context = (cert_path, key_path)
            print(f"[INFO] Serving HTTPS with certificate: {cert_path}")
        else:
            # 'adhoc' auto-generates a temporary self-signed certificate.
            # Fine for local testing; browsers will show a warning since
            # it isn't signed by a trusted authority. Requires pyOpenSSL:
            #   pip install pyopenssl
            ssl_context = "adhoc"
            print("[INFO] Serving HTTPS with a self-signed certificate "
                  "(browsers will warn — for testing only). "
                  "Set SSL_CERT/SSL_KEY to use a real certificate.")

    print(f"[INFO] Starting server on {'https' if use_https else 'http'}://{host}:{port}")
    # debug=False on purpose — never enable the interactive debugger
    # on anything that isn't your own local, trusted machine.
    app.run(host=host, port=port, debug=False, ssl_context=ssl_context)