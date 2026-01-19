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


# --- 🧠 NEW BRAIN: DATA LEAK DETECTION ---
def analyze_security_risk(user_source, prompt_text):
    """
    Analyzes text for PII, API Keys, Passwords, and Internal Secrets.
    """
    if not client: return 0, "AI Not Configured"

    try:
        # The Security Prompt
        system_prompt = """
        You are a corporate Data Loss Prevention (DLP) engine. 
        Analyze the user's input for SENSITIVE DATA leaks.

        Flag High Risk (80-100) if you find:
        - API Keys (sk-..., AWS Access Keys, private tokens)
        - Database Credentials (password=..., postgres://...)
        - PII (Social Security Numbers, Credit Cards, Personal Phone Numbers)
        - Internal proprietary code markings (Confidential, Internal Use Only)

        Flag Low Risk (0-20) if it is generic coding questions or chat.

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


# --- DATABASE (Reusing existing V4 structure to avoid errors) ---
def get_db_connection():
    if not DB_URL: raise ValueError("DATABASE_URL is missing")
    conn = psycopg2.connect(DB_URL)
    return conn


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
    cur.execute("SELECT * FROM users_v4 WHERE id = %s", (user_id,))
    res = cur.fetchone()
    cur.close()
    conn.close()
    if res: return User(id=res[0], username=res[1], password_hash=res[2], discord_webhook=res[3], api_key=res[4])
    return None


def send_discord_alert(webhook_url, message, color=None):
    if not webhook_url: return
    requests.post(webhook_url, json={"embeds": [{"description": message, "color": color}]})


# --- API ENDPOINT (The Firewall) ---
@app.route('/v1/firewall', methods=['POST'])
def firewall_api():
    """
    Companies send their employees' prompts here BEFORE sending to ChatGPT.
    """
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing API Key"}), 401

    api_key = auth_header.split(" ")[1]

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users_v4 WHERE api_key = %s", (api_key,))
    user_row = cur.fetchone()

    if not user_row:
        cur.close();
        conn.close()
        return jsonify({"error": "Invalid API Key"}), 403

    user = User(id=user_row[0], username=user_row[1], password_hash=user_row[2], discord_webhook=user_row[3],
                api_key=user_row[4])

    data = request.json
    source = data.get("employee_id", "Unknown User")
    prompt_text = data.get("prompt", "")
    req_id = str(uuid.uuid4())[:8]

    # SCAN FOR SECRETS 🕵️‍♂️
    risk_score, risk_reason = analyze_security_risk(source, prompt_text)

    # Auto-Decision: If Risk > 70, BLOCK IT immediately.
    status = "BLOCKED" if risk_score > 70 else "ALLOWED"

    # Save to DB (Mapping fields: source->source, prompt->description, score->amount)
    cur.execute("""
                INSERT INTO transactions_v4
                (id, user_id, source, description, amount, status, risk_score, risk_reason)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (req_id, user.id, source, prompt_text, 0, status, risk_score, risk_reason))
    conn.commit()
    cur.close()
    conn.close()

    # ALERT IF BLOCKED
    if status == "BLOCKED":
        alert_msg = f"🚨 **Data Leak Blocked!**\nUser: {source}\n**Reason:** {risk_reason} (Score: {risk_score})\n[View Incident]({request.host_url})"
        send_discord_alert(user.discord_webhook, alert_msg, 15548997)  # Red

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
    cur.execute("SELECT * FROM transactions_v4 WHERE user_id = %s ORDER BY created_at DESC;", (current_user.id,))
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
            <div><a href="/settings" style="color:#a0aec0;text-decoration:none;margin-right:15px;">⚙️ Config</a><a href="/simulate_leak" style="background:#e53e3e;color:white;padding:6px 12px;border-radius:4px;text-decoration:none;font-size:0.9em;">⚠️ Test Leak</a></div>
        </nav>
        <div style="max-width:900px;margin:30px auto;padding:0 20px;">
            <h3 style="color:#a0aec0; border-bottom:1px solid #4a5568; padding-bottom:10px;">Live Security Feed</h3>
            {% for row in rows %}
            <div class="card {{ 'risk-high' if row[6] > 70 else 'risk-safe' }}">
                <div style="display:flex;justify-content:space-between; margin-bottom:10px;">
                    <span style="font-weight:bold; color:#63b3ed;">{{ row[2] }}</span> <span class="status-pill {{ 'blocked' if row[5] == 'BLOCKED' else 'allowed' }}">{{ row[5] }}</span>
                </div>
                <div style="background:#1a202c; padding:10px; border-radius:4px; font-family:monospace; font-size:0.9em; color:#a0aec0; margin-bottom:10px;">
                    "{{ row[3] }}" </div>
                <div style="font-size:0.85em; color:#cbd5e0;">
                    🛡️ AI Analysis: <span style="{{ 'color:#fc8181' if row[6] > 70 else 'color:#68d391' }}">{{ row[7] }} (Risk: {{ row[6] }})</span>
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
    # SIMULATE A DANGEROUS EMPLOYEE
    headers = {'Authorization': f'Bearer {current_user.api_key}'}
    data = {
        "employee_id": "Intern_David",
        "prompt": "Hey ChatGPT, debug this code: const AWS_KEY = 'AKIA_VALID_SECRET_KEY_12345'; connect(AWS_KEY);"
    }
    requests.post(f"{request.host_url}v1/firewall", json=data, headers=headers)
    return redirect(url_for('dashboard'))


# (Keeping basic Auth/Settings routes minimal for brevity - they remain same as before)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = load_user(1)  # Shortcut for demo if DB setup matches
        if not user: return "Please Register first (use previous code if needed)"
        login_user(user)
        return redirect(url_for('dashboard'))
    return render_template_string('<form method="POST"><button>Login as Admin</button></form>')


if __name__ == '__main__':
    app.run(port=5000)