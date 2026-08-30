"""
Code Premium — App Store (Python / Flask version)

A single-file Flask rewrite of the original HTML/JS app store.
Data (apps + the one admin account) is stored in a local SQLite
database instead of the browser's localStorage, so it persists
across restarts and is shared for every visitor.

Run:
    pip install flask
    python app.py
Then open http://127.0.0.1:5000 in your browser.
"""

import os
import sqlite3
import random
from datetime import datetime

from flask import (
    Flask, request, redirect, url_for, session,
    send_from_directory, render_template_string, flash, abort
)
from werkzeug.utils import secure_filename

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
DB_PATH = os.path.join(BASE_DIR, "store.db")

os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = "change-this-secret-key"  # replace with a real secret in production


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
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
            password TEXT NOT NULL
        )
    """)
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


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
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
    )


@app.route("/upload", methods=["POST"])
def upload():
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

    app_id = "app_" + str(int(datetime.utcnow().timestamp() * 1000))

    file_filename = secure_filename(f"{app_id}_{app_file.filename}")
    app_file.save(os.path.join(UPLOAD_DIR, file_filename))
    app_file.stream.seek(0, os.SEEK_END)
    file_size = app_file.stream.tell()

    icon_filename = None
    if icon_file and icon_file.filename != "":
        icon_filename = secure_filename(f"{app_id}_icon_{icon_file.filename}")
        icon_file.save(os.path.join(UPLOAD_DIR, icon_filename))

    rating = round(random.uniform(3.5, 5.0), 1)

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


@app.route("/admin/register", methods=["POST"])
def admin_register():
    if get_admin():
        flash("An account already exists. Please log in.")
        return redirect(url_for("index"))

    first_name = request.form.get("first_name", "").strip()
    last_name = request.form.get("last_name", "").strip()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    confirm = request.form.get("confirm_password", "")

    if not all([first_name, last_name, username, password, confirm]):
        flash("Please fill in all fields.")
        return redirect(url_for("index"))
    if password != confirm:
        flash("❌ Passwords do not match.")
        return redirect(url_for("index"))
    if len(password) < 6:
        flash("❌ Password must be at least 6 characters.")
        return redirect(url_for("index"))

    conn = get_db()
    conn.execute(
        "INSERT INTO admin (id, first_name, last_name, username, password) VALUES (1, ?, ?, ?, ?)",
        (first_name, last_name, username, password),
    )
    conn.commit()
    conn.close()

    flash("🎉 Account created successfully! You can log in now.")
    return redirect(url_for("index"))


@app.route("/admin/login", methods=["POST"])
def admin_login():
    admin = get_admin()
    if not admin:
        flash("No account found. Please create an account first.")
        return redirect(url_for("index"))

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if username == admin["username"] and password == admin["password"]:
        session["admin_logged_in"] = True
        flash("✅ Login successful!")
    else:
        flash("❌ Incorrect username or password.")

    return redirect(url_for("index"))


# Note: no logout route — once logged in, the admin stays logged in
# on this browser session by design (logout option removed).


# ---------------------------------------------------------------------------
# Template (single file, keeps the same dark "Code Premium" look)
# ---------------------------------------------------------------------------

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
.cards-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:12px;}
.card{background:linear-gradient(180deg,#1c1440,#120b2c);border:1px solid #3a2f6b;
  border-radius:16px;padding:12px 8px;text-align:center;}
.thumb{width:78%;aspect-ratio:1/1;margin:0 auto 10px;border-radius:18px;overflow:hidden;display:grid;
  place-items:center;font-size:30px;background:radial-gradient(circle,#3a2f6b,#150f2e);}
.thumb img{width:100%;height:100%;object-fit:cover;}
.card h3{font-size:12.5px;margin:0 0 4px;min-height:32px;}
.card .rating{font-size:12px;color:var(--yellow);}
.card .filesize{font-size:10px;color:var(--muted);margin-top:3px;}
.card-actions{display:flex;gap:5px;margin-top:9px;}
.small-btn{flex:1;padding:6px 4px;border-radius:7px;border:1px solid #4a3b7a;background:#1a1338;
  color:#fff;font-size:10.5px;cursor:pointer;text-decoration:none;display:inline-block;}
.install{background:linear-gradient(90deg,var(--blue),var(--purple));border-color:transparent;}
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
</style>
</head>
<body>

<header class="store-header">
  <div class="header-top">
    <div class="logo-brand">
      <div class="logo-box">⚡</div>
      <div>
        <h1>Code <span>Premium</span></h1>
        <p>{{ apps|length }} Apps</p>
      </div>
    </div>
    <button class="avatar-btn {{ 'admin-active' if logged_in else '' }}"
            onclick="document.getElementById('adminModal').classList.add('show')">
      {{ (admin['first_name'][0] | upper) if (logged_in and admin) else 'N' }}
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

<button class="fab" title="Upload app" onclick="document.getElementById('uploadModal').classList.add('show')">➕</button>

<!-- Upload modal -->
<div class="modal" id="uploadModal">
  <div class="modal-card">
    <h2>🚀 Upload Your App</h2>
    <form method="post" action="{{ url_for('upload') }}" enctype="multipart/form-data">
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

<!-- Admin modal -->
<div class="modal" id="adminModal">
  <div class="modal-card">
    {% if logged_in and admin %}
      <h2>👑 Admin Dashboard</h2>
      <p>Welcome, {{ admin['first_name'] }} {{ admin['last_name'] }}!</p>
      <div style="margin-top:20px;padding:18px;border-radius:14px;background:#101e34;border:1px solid #294568">
        <h3>📊 Store Information</h3>
        <p>Uploaded Apps: <strong>{{ apps|length }}</strong></p>
        <p>Username: <strong>{{ admin['username'] }}</strong></p>
      </div>
      <div class="modal-actions">
        <button type="button" class="cancel" onclick="document.getElementById('adminModal').classList.remove('show')">Close</button>
      </div>
    {% elif admin %}
      <h2>🔐 Admin Panel</h2>
      <p style="color:var(--muted)">Enter your username and password.</p>
      <form method="post" action="{{ url_for('admin_login') }}">
        <div class="form-row"><label>Username</label><input name="username" required></div>
        <div class="form-row"><label>Password</label><input type="password" name="password" required></div>
        <div class="modal-actions">
          <button type="button" class="cancel" onclick="document.getElementById('adminModal').classList.remove('show')">Close</button>
          <button class="btn" type="submit">🔐 Login</button>
        </div>
      </form>
    {% else %}
      <h2>📝 Create Account</h2>
      <p style="color:var(--muted)">No admin account exists yet — create one.</p>
      <form method="post" action="{{ url_for('admin_register') }}">
        <div class="form-row"><label>First Name</label><input name="first_name" required></div>
        <div class="form-row"><label>Last Name</label><input name="last_name" required></div>
        <div class="form-row"><label>Username</label><input name="username" required></div>
        <div class="form-row"><label>Password</label><input type="password" name="password" required></div>
        <div class="form-row"><label>Confirm Password</label><input type="password" name="confirm_password" required></div>
        <div class="modal-actions">
          <button type="button" class="cancel" onclick="document.getElementById('adminModal').classList.remove('show')">Close</button>
          <button class="btn" type="submit">✅ Create Account</button>
        </div>
      </form>
    {% endif %}
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
    app.run(debug=True)
