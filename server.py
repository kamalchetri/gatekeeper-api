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

# Initialize OpenAI Client (Safely)
client = None
if OPENAI_KEY:
    client = OpenAI(api_key=OPENAI_KEY)
else:
    print("⚠️ WARNING: OPENAI_API_KEY not found. AI features will be disabled.")


# --- AI ENGINE 🧠 ---
def analyze_risk_with_ai(source, description, amount):
    """
    Sends transaction details to GPT-4o-mini for risk assessment.
    Returns: (risk_score, risk_reason)
    """
    # Fallback if no key provided
    if not client:
        return 0, "AI Not Configured (Key Missing)"

    try:
        # The Prompt: We teach the AI how to be a fraud analyst
        prompt = f"""
        Analyze this financial transaction for fraud risk.
        Transaction Source: {source}
        Description: {description}
        Amount: ${amount}

        Return a JSON object with two fields:
        1. "risk_score" (0 to 100, where 100 is certain fraud).
        2. "risk_reason" (A short, 5-word explanation).
        """

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a strict financial security AI. Output JSON only."},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"}
        )

        # Parse the JSON response from the AI
        result = json.loads(response.choices[0].message.content)
        return result.get('risk_score', 50), result.get('risk_reason', "Manual Review Needed")

    except Exception as e:
        print(f"❌ AI Error: {e}")
        return 50, "AI Service Error"


# --- DATABASE SETUP ---
def get_db_connection():
    if not DB_URL: raise ValueError("DATABASE_URL is missing")
    conn = psycopg2.connect(DB_URL)
    return conn


def init_db():
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Users Table (v4)
        cur.execute("""
                    CREATE TABLE IF NOT EXISTS users_v4
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

        # Transactions Table (v4)
        cur.execute("""
                    CREATE TABLE IF NOT EXISTS transactions_v4
                    (
                        id
                        VARCHAR
                    (
                        10
                    ) PRIMARY KEY,
                        user_id INTEGER REFERENCES users_v4
                    (
                        id
                    ),
                        source VARCHAR
                    (
                        100
                    ),
                        description TEXT,
                        amount DECIMAL
                    (
                        10,
                        2
                    ),
                        status VARCHAR
                    (
                        20
                    ),
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
    cur.execute("SELECT * FROM users_v4 WHERE id = %s", (user_id,))
    res = cur.fetchone()
    cur.close()
    conn.close()
    if res: return User(id=res[0], username=res[1], password_hash=res[2], discord_webhook=res[3], api_key=res[4])
    return None


def send_discord_alert(webhook_url, message, color=None):
    if not webhook_url: return
    if not color: color = 3447003
    try:
        requests.post(webhook_url, json={"embeds": [{"description": message, "color": color}]})
    except:
        pass


# --- API ENDPOINT (For External Software) ---
@app.route('/v1/gatekeeper', methods=['POST'])
def gatekeeper_api():
    """
    The Universal API Endpoint.
    Your friend sends traffic here using their API Key.
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
    source = data.get("source", "API Request")
    description = data.get("description", "Unknown")
    amount = float(data.get("amount", 0.0))
    req_id = str(uuid.uuid4())[:8]

    # CALL THE AI BRAIN
    risk_score, risk_reason = analyze_risk_with_ai(source, description, amount)

    cur.execute("""
                INSERT INTO transactions_v4
                (id, user_id, source, description, amount, status, risk_score, risk_reason)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (req_id, user.id, source, description, amount, "PENDING", risk_score, risk_reason))
    conn.commit()
    cur.close()
    conn.close()

    # ALERT
    color = 15548997 if risk_score > 75 else 3447003  # Red for High Risk
    alert_msg = f"🚨 **New Request**\nSource: {source}\nAmount: ${amount}\n**AI Risk:** {risk_score}/100 ({risk_reason})\n[Open Dashboard]({request.host_url})"
    send_discord_alert(user.discord_webhook, alert_msg, color)

    return jsonify({
        "status": "queued",
        "id": req_id,
        "risk_assessment": {"score": risk_score, "reason": risk_reason}
    })


# --- UI ROUTES ---

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
            cur.execute("INSERT INTO users_v4 (username, password_hash, api_key) VALUES (%s, %s, %s) RETURNING id",
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
        cur.execute("SELECT * FROM users_v4 WHERE username = %s", (username,))
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
        cur.execute("UPDATE users_v4 SET discord_webhook = %s WHERE id = %s", (new_webhook, current_user.id))
        conn.commit()
        cur.close()
        conn.close()
        current_user.discord_webhook = new_webhook
        msg = "✅ Saved!"

    html = """
    <!DOCTYPE html>
    <html><head><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Developer Settings</title>
    <style>body{font-family:system-ui;background:#f7fafc;padding:20px;text-align:center;} .card{background:white;padding:30px;max-width:600px;margin:30px auto;border-radius:12px;box-shadow:0 2px 5px rgba(0,0,0,0.05);text-align:left;} input{width:100%;padding:10px;margin:10px 0;border:1px solid #ddd;border-radius:6px;box-sizing:border-box;} button{padding:10px 20px;background:#333;color:white;border:none;border-radius:6px;cursor:pointer;} .api-box{background:#1a202c;color:#48bb78;padding:15px;border-radius:6px;font-family:monospace;word-break:break-all;} label{font-weight:bold;font-size:0.9em;color:#4a5568;}</style></head>
    <body>
        <div class="card">
            <h2>⚙️ Developer Settings</h2>
            <p style="color:green;font-weight:bold;">{{ msg }}</p>
            <label>1. Your API Key (Share with Developer Friend)</label>
            <div class="api-box">{{ user.api_key }}</div>
            <p style="font-size:0.8em;color:#718096;">Use this key to authenticate requests from your billing software.</p>
            <hr style="border:0;border-top:1px solid #eee;margin:20px 0;">
            <form method="POST">
                <label>2. Your Discord Webhook (Receive Alerts)</label>
                <input type="text" name="webhook" placeholder="https://discord.com/api/webhooks/..." value="{{ user.discord_webhook or '' }}">
                <button>Save Webhook</button>
            </form>
            <div style="margin-top:30px;text-align:center;"><a href="/" style="color:#007bff;text-decoration:none;">← Back to Dashboard</a></div>
        </div>
    </body></html>
    """
    return render_template_string(html, msg=msg, user=current_user)


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
    <html><head><meta name="viewport" content="width=device-width, initial-scale=1.0"><meta http-equiv="refresh" content="10"><title>Dashboard</title>
    <style>:root{--bg:#f7fafc;} body{font-family:system-ui;background:var(--bg);margin:0;padding-bottom:40px;} .navbar{background:white;padding:15px 20px;box-shadow:0 2px 4px rgba(0,0,0,0.05);display:flex;justify-content:space-between;align-items:center;} .card{background:white;padding:20px;border-radius:12px;box-shadow:0 2px 5px rgba(0,0,0,0.05);margin-bottom:20px;border-left:5px solid #ccc;} .status-pill{padding:5px 10px;border-radius:15px;font-size:0.8em;font-weight:bold;} .approved{background:#c6f6d5;color:#276749;} .rejected{background:#fed7d7;color:#9b2c2c;} .btn{padding:8px 16px;border-radius:6px;text-decoration:none;color:white;font-weight:bold;margin-right:5px;} .risk-high{border-left-color:#f56565;} .risk-low{border-left-color:#48bb78;} .risk-badge{font-size:0.8em;background:#edf2f7;padding:3px 8px;border-radius:4px;color:#4a5568;margin-top:5px;display:inline-block;}</style></head>
    <body>
        <nav class="navbar">
            <div><b>Gatekeeper AI</b> | {{ user.username }}</div>
            <div><a href="/settings" style="text-decoration:none; margin-right:15px;">⚙️ Keys</a><a href="/simulate_ai_demo" style="background:#333;color:white;padding:8px 15px;border-radius:20px;font-size:0.8em;text-decoration:none;">🤖 AI Test</a><a href="/logout" style="margin-left:15px;text-decoration:none;color:red;">Log Out</a></div>
        </nav>
        <div style="max-width:1000px;margin:30px auto;padding:0 20px;">
            {% for row in rows %}
            <div class="card {{ 'risk-high' if row[6] and row[6] > 50 else 'risk-low' }}">
                <div style="display:flex;justify-content:space-between;">
                    <h3>{{ row[2] }} <span style="font-weight:normal;color:#718096;">${{ row[4] }}</span></h3>
                    <div class="risk-badge">Risk: {{ row[6] }}/100</div>
                </div>
                <p>{{ row[3] }}</p>
                <p style="font-size:0.85em;color:#e53e3e;">AI Insight: {{ row[7] }}</p>
                {% if row[5] == 'PENDING' %}
                    <div style="margin-top:10px;">
                        <a href="/approve/{{ row[0] }}" class="btn" style="background:#48bb78;">Approve</a>
                        <a href="/reject/{{ row[0] }}" class="btn" style="background:#f56565;">Reject</a>
                    </div>
                {% else %}
                    <span class="status-pill {{ 'approved' if row[5] == 'APPROVED' else 'rejected' }}">{{ row[5] }}</span>
                {% endif %}
            </div>
            {% endfor %}
        </div>
    </body></html>
    """
    return render_template_string(html, rows=rows, user=current_user)


@app.route('/simulate_ai_demo')
@login_required
def simulate_ai_demo():
    # TEST FUNCTION: Creates a fake suspicious request to prove AI is working
    headers = {'Authorization': f'Bearer {current_user.api_key}'}
    # We purposefully make this description "scary" so the AI flags it
    data = {
        "source": "Unknown Offshore Vendor",
        "description": "Large transfer to unverified crypto wallet",
        "amount": 4999.00
    }
    try:
        requests.post(f"{request.host_url}v1/gatekeeper", json=data, headers=headers, timeout=5)
    except:
        pass  # Ignore timeout, just redirect
    return redirect(url_for('dashboard'))


@app.route('/approve/<req_id>')
@login_required
def approve(req_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE transactions_v4 SET status = 'APPROVED' WHERE id = %s AND user_id = %s",
                (req_id, current_user.id))
    conn.commit()
    cur.close()
    conn.close()
    send_discord_alert(current_user.discord_webhook, f"✅ **Approved** Transaction {req_id}", 5763719)
    return redirect(url_for('dashboard'))


@app.route('/reject/<req_id>')
@login_required
def reject(req_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE transactions_v4 SET status = 'REJECTED' WHERE id = %s AND user_id = %s",
                (req_id, current_user.id))
    conn.commit()
    cur.close()
    conn.close()
    send_discord_alert(current_user.discord_webhook, f"❌ **Rejected** Transaction {req_id}", 15548997)
    return redirect(url_for('dashboard'))


@app.route('/logout')
@login_required
def logout_route():
    logout_user()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(port=5000)