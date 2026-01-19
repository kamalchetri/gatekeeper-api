import os
import uuid
import json
import psycopg2
import requests
import secrets
from flask import Flask, request, jsonify, render_template_string, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from openai import OpenAI

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'default_secret_key')

# --- CONFIGURATION ---
DB_URL = os.environ.get('DATABASE_URL')
OPENAI_KEY = os.environ.get('OPENAI_API_KEY')

client = None
if OPENAI_KEY:
    client = OpenAI(api_key=OPENAI_KEY)


# --- 🧠 BRAIN: DATA LEAK DETECTION ---
def analyze_security_risk(prompt_text):
    """
    Analyzes text for PII, API Keys, Passwords.
    """
    if not client: return 0, "AI Not Configured"

    try:
        system_prompt = """
        You are a Data Loss Prevention (DLP) engine. 
        Analyze the user's input for SENSITIVE DATA leaks.

        Flag High Risk (80-100) if you find:
        - API Keys (sk-..., AWS Access Keys)
        - Database Credentials
        - PII (Social Security Numbers, Phone Numbers)
        - Internal proprietary code markings

        Flag Low Risk (0-20) if it is generic chat.

        Return JSON: {"risk_score": 0-100, "risk_reason": "short explanation"}
        """

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"User Input to Scan: {prompt_text}"}
            ],
            response_format={"type": "json_object"}
        )

        result = json.loads(response.choices[0].message.content)
        return result.get('risk_score', 0), result.get('risk_reason', "Safe")

    except Exception as e:
        print(f"❌ AI Error: {e}")
        return 50, "Scan Error"


# --- DATABASE (Moving to v5 for Clean Slate) ---
def get_db_connection():
    if not DB_URL: raise ValueError("DATABASE_URL is missing")
    conn = psycopg2.connect(DB_URL)
    return conn


def init_db():
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Users Table (v5)
        cur.execute("""
                    CREATE TABLE IF NOT EXISTS users_v5
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
                        discord_webhook TEXT,
                        api_key VARCHAR
                    (
                        64
                    ) UNIQUE
                        );
                    """)

        # Transactions Table (v5) - Storing Security Logs
        cur.execute("""
                    CREATE TABLE IF NOT EXISTS transactions_v5
                    (
                        id
                        VARCHAR
                    (
                        10
                    ) PRIMARY KEY,
                        user_id INTEGER REFERENCES users_v5
                    (
                        id
                    ),
                        source VARCHAR
                    (
                        100
                    ), -- The Employee Name
                        description TEXT, -- The Prompt Text
                        status VARCHAR
                    (
                        20
                    ), -- BLOCKED / ALLOWED
                        risk_score INTEGER,
                        risk_reason TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        );
                    """)
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"❌ DB Init Error: {e}")


if DB_URL: init_db()

# --- AUTH SETUP ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin):
    def __init__(self, id, username, password_hash, discord_webhook, api_key):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.discord_webhook = discord_webhook
        self.api_key = api_key


@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users_v5 WHERE id = %s", (user_id,))
    res = cur.fetchone()
    cur.close()
    conn.close()
    if res: return User(id=res[0], username=res[1], password_hash=res[2], discord_webhook=res[3], api_key=res[4])
    return None


def send_discord_alert(webhook_url, message, color=None):
    if not webhook_url: return
    try:
        requests.post(webhook_url, json={"embeds": [{"description": message, "color": color}]})
    except:
        pass


# --- API ENDPOINT (The Firewall) ---
@app.route('/v1/firewall', methods=['POST'])
def firewall_api():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing API Key"}), 401

    api_key = auth_header.split(" ")[1]

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users_v5 WHERE api_key = %s", (api_key,))
    user_row = cur.fetchone()

    if not user_row:
        cur.close();
        conn.close()
        return jsonify({"error": "Invalid API Key"}), 403

    user = User(id=user_row[0], username=user_row[1], password_hash=user_row[2], discord_webhook=user_row[3],
                api_key=user_row[4])

    data = request.json
    source = data.get("employee_id", "Unknown")
    prompt_text = data.get("prompt", "")
    req_id = str(uuid.uuid4())[:8]

    # SCAN 🕵️‍♂️
    risk_score, risk_reason = analyze_security_risk(prompt_text)
    status = "BLOCKED" if risk_score > 70 else "ALLOWED"

    cur.execute("""
                INSERT INTO transactions_v5
                    (id, user_id, source, description, status, risk_score, risk_reason)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (req_id, user.id, source, prompt_text, status, risk_score, risk_reason))
    conn.commit()
    cur.close()
    conn.close()

    if status == "BLOCKED":
        alert_msg = f"🚨 **Data Leak Blocked!**\nUser: {source}\n**Reason:** {risk_reason} (Score: {risk_score})\n[View Incident]({request.host_url})"
        send_discord_alert(user.discord_webhook, alert_msg, 15548997)

    return jsonify({
        "status": status,
        "id": req_id,
        "risk_assessment": {"score": risk_score, "reason": risk_reason}
    })


# --- UI ROUTES ---
@app.route('/')
@login_required
def dashboard():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM transactions_v5 WHERE user_id = %s ORDER BY created_at DESC;", (current_user.id,))
    rows = cur.fetchall()
    cur.close()
    conn.close()

    html = """
    <!DOCTYPE html>
    <html><head><meta name="viewport" content="width=device-width, initial-scale=1.0"><meta http-equiv="refresh" content="10"><title>Sentinel AI</title>
    <style>:root{--bg:#1a202c; --card:#2d3748; --text:#edf2f7;} body{font-family:system-ui;background:var(--bg);color:var(--text);margin:0;padding-bottom:40px;} .navbar{background:#2d3748;padding:15px 20px;border-bottom:1px solid #4a5568;display:flex;justify-content:space-between;align-items:center;} .card{background:var(--card);padding:20px;border-radius:8px;margin-bottom:15px;border-left:5px solid #718096;} .status-pill{padding:4px 10px;border-radius:4px;font-size:0.8em;font-weight:bold;} .blocked{background:#e53e3e;color:white;} .allowed{background:#48bb78;color:white;} .risk-high{border-left-color:#e53e3e;} .risk-safe{border-left-color:#48bb78;}</style></head>
    <body>
        <nav class="navbar">
            <div style="font-weight:bold; letter-spacing:1px;">🔒 SENTINEL <span style="color:#a0aec0;font-weight:normal;">| AI Firewall</span></div>
            <div><a href="/settings" style="color:#a0aec0;text-decoration:none;margin-right:15px;">⚙️ Config</a><a href="/simulate_leak" style="background:#e53e3e;color:white;padding:6px 12px;border-radius:4px;text-decoration:none;font-size:0.9em;">⚠️ Test Leak</a><a href="/logout" style="margin-left:15px;color:#a0aec0;text-decoration:none;">Log Out</a></div>
        </nav>
        <div style="max-width:900px;margin:30px auto;padding:0 20px;">
            <h3 style="color:#a0aec0; border-bottom:1px solid #4a5568; padding-bottom:10px;">Live Security Feed</h3>
            {% if not rows %}
                <div style="text-align:center; padding:40px; color:#718096;">System Secure. No incidents logged.</div>
            {% endif %}
            {% for row in rows %}
            <div class="card {{ 'risk-high' if row[5] > 70 else 'risk-safe' }}">
                <div style="display:flex;justify-content:space-between; margin-bottom:10px;">
                    <span style="font-weight:bold; color:#63b3ed;">{{ row[2] }}</span>
                    <span class="status-pill {{ 'blocked' if row[4] == 'BLOCKED' else 'allowed' }}">{{ row[4] }}</span>
                </div>
                <div style="background:#1a202c; padding:10px; border-radius:4px; font-family:monospace; font-size:0.9em; color:#a0aec0; margin-bottom:10px;">
                    "{{ row[3] }}"
                </div>
                <div style="font-size:0.85em; color:#cbd5e0;">
                    🛡️ AI Analysis: <span style="{{ 'color:#fc8181' if row[5] > 70 else 'color:#68d391' }}">{{ row[6] }} (Risk: {{ row[5] }})</span>
                </div>
            </div>
            {% endfor %}
        </div>
    </body></html>
    """
    return render_template_string(html, rows=rows, user=current_user)


@app.route('/simulate_leak')
@login_required
def simulate_leak():
    # FIXED: Run logic INTERNALLY to avoid Server Deadlock (500 Error)
    source = "Intern_David"
    prompt_text = "Hey ChatGPT, debug this code: const AWS_KEY = 'AKIA_VALID_SECRET_KEY_12345'; connect(AWS_KEY);"
    req_id = str(uuid.uuid4())[:8]

    # 1. AI Analysis
    risk_score, risk_reason = analyze_security_risk(prompt_text)
    status = "BLOCKED" if risk_score > 70 else "ALLOWED"

    # 2. Direct DB Insert (No network call)
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
                INSERT INTO transactions_v5
                    (id, user_id, source, description, status, risk_score, risk_reason)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (req_id, current_user.id, source, prompt_text, status, risk_score, risk_reason))
    conn.commit()
    cur.close()
    conn.close()

    return redirect(url_for('dashboard'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    message = ""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_pw = generate_password_hash(password)
        new_api_key = "sk_live_" + secrets.token_hex(16)
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("INSERT INTO users_v5 (username, password_hash, api_key) VALUES (%s, %s, %s) RETURNING id",
                        (username, hashed_pw, new_api_key))
            user_id = cur.fetchone()[0]
            conn.commit()
            cur.close()
            conn.close()
            user = User(id=user_id, username=username, password_hash=hashed_pw, discord_webhook=None,
                        api_key=new_api_key)
            login_user(user)
            return redirect(url_for('settings'))
        except psycopg2.errors.UniqueViolation:
            message = "❌ Username taken."
        except Exception as e:
            message = f"❌ Error: {e}"

    return render_template_string("""
    <!DOCTYPE html><html><head><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Sign Up</title>
    <style>body{font-family:system-ui;background:#f0f2f5;height:100vh;display:flex;align-items:center;justify-content:center;margin:0;} .card{background:white;padding:40px;border-radius:16px;box-shadow:0 4px 12px rgba(0,0,0,0.1);text-align:center;width:300px;} input{width:100%;padding:10px;margin:8px 0;border:1px solid #ddd;border-radius:6px;} button{width:100%;padding:10px;margin-top:10px;background:#2ecc71;color:white;border:none;border-radius:6px;cursor:pointer;font-weight:bold;}</style></head><body><div class="card"><h2>Create Account</h2><p style="color:red">{{message}}</p><form method="POST"><input type="text" name="username" placeholder="Username" required><input type="password" name="password" placeholder="Password" required><button>Sign Up</button></form><a href="/login" style="display:block;margin-top:15px;color:#007bff;">Login</a></div></body></html>
    """, message=message)


@app.route('/login', methods=['GET', 'POST'])
def login():
    message = ""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users_v5 WHERE username = %s", (username,))
        row = cur.fetchone()
        cur.close()
        conn.close()
        if row and check_password_hash(row[2], password):
            user = User(id=row[0], username=row[1], password_hash=row[2], discord_webhook=row[3], api_key=row[4])
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            message = "❌ Invalid Credentials"

    return render_template_string("""
    <!DOCTYPE html><html><head><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Login</title>
    <style>body{font-family:system-ui;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);height:100vh;display:flex;align-items:center;justify-content:center;margin:0;} .card{background:white;padding:40px;border-radius:16px;box-shadow:0 10px 25px rgba(0,0,0,0.2);text-align:center;width:300px;} input{width:100%;padding:10px;margin:8px 0;border:1px solid #ddd;border-radius:6px;} button{width:100%;padding:10px;margin-top:10px;background:#667eea;color:white;border:none;border-radius:6px;cursor:pointer;font-weight:bold;}</style></head><body><div class="card"><span style="font-size:40px;">🛡️</span><h2>Welcome Back</h2><p style="color:red">{{message}}</p><form method="POST"><input type="text" name="username" placeholder="Username" required><input type="password" name="password" placeholder="Password" required><button>Sign In</button></form><a href="/register" style="display:block;margin-top:15px;color:#667eea;">Create Account</a></div></body></html>
    """, message=message)


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    msg = ""
    if request.method == 'POST':
        new_webhook = request.form['webhook']
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE users_v5 SET discord_webhook = %s WHERE id = %s", (new_webhook, current_user.id))
        conn.commit()
        cur.close()
        conn.close()
        current_user.discord_webhook = new_webhook
        msg = "✅ Saved!"

    html = """
    <!DOCTYPE html>
    <html><head><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Settings</title>
    <style>body{font-family:system-ui;background:#f7fafc;padding:20px;text-align:center;} .card{background:white;padding:30px;max-width:600px;margin:30px auto;border-radius:12px;box-shadow:0 2px 5px rgba(0,0,0,0.05);text-align:left;} input{width:100%;padding:10px;margin:10px 0;border:1px solid #ddd;border-radius:6px;box-sizing:border-box;} button{padding:10px 20px;background:#333;color:white;border:none;border-radius:6px;cursor:pointer;} .api-box{background:#1a202c;color:#48bb78;padding:15px;border-radius:6px;font-family:monospace;word-break:break-all;} label{font-weight:bold;font-size:0.9em;color:#4a5568;}</style></head>
    <body>
        <div class="card">
            <h2>⚙️ API Config</h2>
            <p style="color:green;font-weight:bold;">{{ msg }}</p>
            <label>API Key (For your Internal Tools)</label>
            <div class="api-box">{{ user.api_key }}</div>
            <hr style="border:0;border-top:1px solid #eee;margin:20px 0;">
            <form method="POST">
                <label>Discord Webhook (For Alerts)</label>
                <input type="text" name="webhook" placeholder="https://discord.com/api/webhooks/..." value="{{ user.discord_webhook or '' }}">
                <button>Save Webhook</button>
            </form>
            <div style="margin-top:30px;text-align:center;"><a href="/" style="color:#007bff;text-decoration:none;">← Back to Dashboard</a></div>
        </div>
    </body></html>
    """
    return render_template_string(html, msg=msg, user=current_user)


@app.route('/logout')
@login_required
def logout_route():
    logout_user()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(port=5000)