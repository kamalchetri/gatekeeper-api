import os
import uuid
import psycopg2
import requests
from flask import Flask, request, jsonify, render_template_string, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'default_secret_key')
DB_URL = os.environ.get('DATABASE_URL')


# --- DB HELPERS ---
def get_db_connection():
    if not DB_URL: raise ValueError("DATABASE_URL is missing")
    conn = psycopg2.connect(DB_URL)
    return conn


def init_db():
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # 1. NEW Users Table (v3 - Adds Webhook Column)
        cur.execute("""
                    CREATE TABLE IF NOT EXISTS users_v3
                    (
                        id
                        SERIAL
                        PRIMARY
                        KEY,
                        username
                        VARCHAR
                    (
                        50
                    ) UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        discord_webhook TEXT -- <--- NEW: Stores user's personal alert link
                        );
                    """)

        # 2. NEW Transactions Table (v3)
        cur.execute("""
                    CREATE TABLE IF NOT EXISTS transactions_v3
                    (
                        id
                        VARCHAR
                    (
                        10
                    ) PRIMARY KEY,
                        user_id INTEGER REFERENCES users_v3
                    (
                        id
                    ),
                        source VARCHAR
                    (
                        100
                    ),
                        description TEXT,
                        status VARCHAR
                    (
                        20
                    ),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        );
                    """)

        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"❌ DB Init Error: {e}")


if DB_URL: init_db()

# --- LOGIN SETUP ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin):
    def __init__(self, id, username, password_hash, discord_webhook):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.discord_webhook = discord_webhook  # <--- User now knows their own webhook


@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users_v3 WHERE id = %s", (user_id,))
    res = cur.fetchone()
    cur.close()
    conn.close()
    # Row: 0=id, 1=username, 2=pass, 3=webhook
    if res: return User(id=res[0], username=res[1], password_hash=res[2], discord_webhook=res[3])
    return None


# --- ALERT SYSTEM (Dynamic) ---
def send_alert(user, message, color=None):
    """Sends alert to the SPECIFIC user's webhook, not the global one."""
    if not user.discord_webhook: return  # Do nothing if they haven't set it up

    if not color:
        if "Approved" in message:
            color = 5763719  # Green
        elif "Rejected" in message:
            color = 15548997  # Red
        else:
            color = 3447003  # Blue

    data = {"embeds": [{"description": message, "color": color}]}
    try:
        requests.post(user.discord_webhook, json=data)
    except Exception as e:
        print(f"❌ Discord Error: {e}")


# --- ROUTES ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    message = ""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_pw = generate_password_hash(password)
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("INSERT INTO users_v3 (username, password_hash) VALUES (%s, %s) RETURNING id",
                        (username, hashed_pw))
            user_id = cur.fetchone()[0]
            conn.commit()
            cur.close()
            conn.close()
            user = User(id=user_id, username=username, password_hash=hashed_pw, discord_webhook=None)
            login_user(user)
            return redirect(url_for('settings'))  # Send new users to Settings first!
        except psycopg2.errors.UniqueViolation:
            message = "❌ Username taken."
        except Exception as e:
            message = f"❌ Error: {e}"

    html = """
    <!DOCTYPE html>
    <html>
    <head><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Sign Up</title>
    <style>body{font-family:system-ui;background:#f0f2f5;height:100vh;display:flex;align-items:center;justify-content:center;margin:0;} .card{background:white;padding:40px;border-radius:16px;box-shadow:0 4px 12px rgba(0,0,0,0.1);text-align:center;width:300px;} input{width:100%;padding:10px;margin:8px 0;border:1px solid #ddd;border-radius:6px;} button{width:100%;padding:10px;margin-top:10px;background:#2ecc71;color:white;border:none;border-radius:6px;cursor:pointer;font-weight:bold;}</style>
    </head><body><div class="card"><h2>Create Account</h2><p style="color:red">{{message}}</p><form method="POST"><input type="text" name="username" placeholder="Username" required><input type="password" name="password" placeholder="Password" required><button>Sign Up</button></form><a href="/login" style="display:block;margin-top:15px;color:#007bff;">Login</a></div></body></html>
    """
    return render_template_string(html, message=message)


@app.route('/login', methods=['GET', 'POST'])
def login():
    message = ""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users_v3 WHERE username = %s", (username,))
        row = cur.fetchone()
        cur.close()
        conn.close()
        if row and check_password_hash(row[2], password):
            user = User(id=row[0], username=row[1], password_hash=row[2], discord_webhook=row[3])
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            message = "❌ Invalid Credentials"

    html = """
    <!DOCTYPE html>
    <html>
    <head><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Login</title>
    <style>body{font-family:system-ui;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);height:100vh;display:flex;align-items:center;justify-content:center;margin:0;} .card{background:white;padding:40px;border-radius:16px;box-shadow:0 10px 25px rgba(0,0,0,0.2);text-align:center;width:300px;} input{width:100%;padding:10px;margin:8px 0;border:1px solid #ddd;border-radius:6px;} button{width:100%;padding:10px;margin-top:10px;background:#667eea;color:white;border:none;border-radius:6px;cursor:pointer;font-weight:bold;}</style>
    </head><body><div class="card"><span style="font-size:40px;">🛡️</span><h2>Welcome Back</h2><p style="color:red">{{message}}</p><form method="POST"><input type="text" name="username" placeholder="Username" required><input type="password" name="password" placeholder="Password" required><button>Sign In</button></form><a href="/register" style="display:block;margin-top:15px;color:#667eea;">Create Account</a></div></body></html>
    """
    return render_template_string(html, message=message)


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    msg = ""
    if request.method == 'POST':
        new_webhook = request.form['webhook']
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE users_v3 SET discord_webhook = %s WHERE id = %s", (new_webhook, current_user.id))
        conn.commit()
        cur.close()
        conn.close()
        # Update session
        current_user.discord_webhook = new_webhook
        msg = "✅ Webhook Saved! Try a test alert."

    html = """
    <!DOCTYPE html>
    <html>
    <head><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Settings</title>
    <style>body{font-family:system-ui;background:#f7fafc;padding:20px;text-align:center;} .card{background:white;padding:30px;max-width:500px;margin:30px auto;border-radius:12px;box-shadow:0 2px 5px rgba(0,0,0,0.05);} input{width:100%;padding:10px;margin:10px 0;border:1px solid #ddd;border-radius:6px;box-sizing:border-box;} button{padding:10px 20px;background:#333;color:white;border:none;border-radius:6px;cursor:pointer;} a{color:#007bff;text-decoration:none;}</style>
    </head>
    <body>
        <div class="card">
            <h2>⚙️ Notification Settings</h2>
            <p>Paste your <b>Discord Webhook URL</b> below to receive alerts.</p>
            <p style="color:green;font-weight:bold;">{{ msg }}</p>
            <form method="POST">
                <input type="text" name="webhook" placeholder="https://discord.com/api/webhooks/..." value="{{ user.discord_webhook or '' }}" required>
                <button>Save Settings</button>
            </form>
            <br>
            <a href="/">← Back to Dashboard</a>
        </div>
    </body>
    </html>
    """
    return render_template_string(html, msg=msg, user=current_user)


@app.route('/')
@login_required
def dashboard():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM transactions_v3 WHERE user_id = %s ORDER BY created_at DESC;", (current_user.id,))
    rows = cur.fetchall()
    cur.close()
    conn.close()

    html = """
    <!DOCTYPE html>
    <html>
    <head><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Dashboard</title>
    <style>:root{--primary:#667eea;--bg:#f7fafc;} body{font-family:system-ui;background:var(--bg);margin:0;padding-bottom:40px;} .navbar{background:white;padding:15px 20px;box-shadow:0 2px 4px rgba(0,0,0,0.05);display:flex;justify-content:space-between;align-items:center;} .card{background:white;padding:20px;border-radius:12px;box-shadow:0 2px 5px rgba(0,0,0,0.05);margin-bottom:20px;} .status-pill{padding:5px 10px;border-radius:15px;font-size:0.8em;font-weight:bold;} .approved{background:#c6f6d5;color:#276749;} .rejected{background:#fed7d7;color:#9b2c2c;} .btn{padding:8px 16px;border-radius:6px;text-decoration:none;color:white;font-weight:bold;margin-right:5px;} .demo-btn{background:#333;color:white;padding:8px 15px;border-radius:20px;font-size:0.8em;text-decoration:none;}</style>
    </head>
    <body>
        <nav class="navbar">
            <div><b>Gatekeeper</b> | {{ user.username }}</div>
            <div>
                <a href="/settings" style="text-decoration:none; margin-right:15px;">⚙️</a>
                <a href="/simulate_demo" class="demo-btn">⚡ Test</a>
                <a href="/logout" style="margin-left:15px;text-decoration:none;color:red;">Log Out</a>
            </div>
        </nav>
        <div style="max-width:1000px;margin:30px auto;padding:0 20px;">
            {% if not user.discord_webhook %}
                <div style="background:#fff3cd;color:#856404;padding:15px;border-radius:8px;margin-bottom:20px;text-align:center;">
                    ⚠️ You haven't set up notifications yet. <a href="/settings">Go to Settings</a>
                </div>
            {% endif %}

            {% for row in rows %}
            <div class="card">
                <h3>{{ row[2] }}</h3><p>{{ row[3] }}</p>
                {% if row[4] == 'PENDING' %}
                    <a href="/approve/{{ row[0] }}" class="btn" style="background:#48bb78;">Approve</a>
                    <a href="/reject/{{ row[0] }}" class="btn" style="background:#f56565;">Reject</a>
                {% else %}
                    <span class="status-pill {{ 'approved' if row[4] == 'APPROVED' else 'rejected' }}">{{ row[4] }}</span>
                {% endif %}
            </div>
            {% endfor %}
        </div>
    </body>
    </html>
    """
    return render_template_string(html, rows=rows, user=current_user)


@app.route('/simulate_demo')
@login_required
def simulate_demo():
    conn = get_db_connection()
    cur = conn.cursor()
    req_id = str(uuid.uuid4())[:8]
    cur.execute("INSERT INTO transactions_v3 (id, user_id, source, description, status) VALUES (%s, %s, %s, %s, %s)",
                (req_id, current_user.id, "Demo Bot", "Requesting $500", "PENDING"))
    conn.commit()
    cur.close()
    conn.close()

    # 🔔 Send Alert to THIS USER'S webhook
    if current_user.discord_webhook:
        send_alert(current_user,
                   f"🚨 **New Request!**\nSource: Demo Bot\nAmount: $500\n[Open Dashboard]({request.host_url})")

    return redirect(url_for('dashboard'))


@app.route('/approve/<req_id>')
@login_required
def approve(req_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE transactions_v3 SET status = 'APPROVED' WHERE id = %s AND user_id = %s",
                (req_id, current_user.id))
    conn.commit()
    cur.close()
    conn.close()

    send_alert(current_user, f"✅ **Approved**\nTransaction {req_id} authorized.")
    return redirect(url_for('dashboard'))


@app.route('/reject/<req_id>')
@login_required
def reject(req_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE transactions_v3 SET status = 'REJECTED' WHERE id = %s AND user_id = %s",
                (req_id, current_user.id))
    conn.commit()
    cur.close()
    conn.close()

    send_alert(current_user, f"❌ **Rejected**\nTransaction {req_id} denied.")
    return redirect(url_for('dashboard'))


@app.route('/logout')
@login_required
def logout_route():
    logout_user()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(port=5000)