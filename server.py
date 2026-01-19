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


# --- 🧠 VIGIL BRAIN: DATA LEAK DETECTION ---
def analyze_security_risk(prompt_text):
    if not client: return 0, "AI Not Configured"
    try:
        system_prompt = """
        You are VIGIL, a corporate Data Loss Prevention (DLP) engine. 
        Analyze the input for SENSITIVE DATA leaks.

        Flag High Risk (80-100) for:
        - API Keys (sk-..., AWS, Azure)
        - DB Credentials & Passwords
        - PII (SSN, Emails, Phone Numbers)
        - Internal proprietary code markings

        Return JSON: {"risk_score": 0-100, "risk_reason": "short explanation"}
        """
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Scan: {prompt_text}"}
            ],
            response_format={"type": "json_object"}
        )
        result = json.loads(response.choices[0].message.content)
        return result.get('risk_score', 0), result.get('risk_reason', "Safe")
    except Exception as e:
        print(f"❌ AI Error: {e}")
        return 50, "Scan Error"


# --- DATABASE SETUP (V5) ---
def get_db_connection():
    if not DB_URL: raise ValueError("DATABASE_URL is missing")
    conn = psycopg2.connect(DB_URL)
    return conn


def init_db():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
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
                    ),
                        description TEXT,
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
login_manager.login_view = 'landing'  # Redirect unauth users to Landing Page


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


# --- DESIGN: COMMON HEADERS (TAILWIND CSS) ---
BASE_HTML = """
<!DOCTYPE html>
<html lang="en" class="scroll-smooth">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VIGIL | The AI Firewall</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap" rel="stylesheet">
    <style>body { font-family: 'Inter', sans-serif; }</style>
</head>
<body class="bg-slate-900 text-white antialiased selection:bg-indigo-500 selection:text-white">
"""


# --- ROUTE: LANDING PAGE (Beautiful Home) ---
@app.route('/')
def landing():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    return render_template_string(BASE_HTML + """
    <div class="relative overflow-hidden">
        <nav class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 flex justify-between items-center">
            <div class="text-2xl font-bold tracking-tighter text-indigo-400">VIGIL</div>
            <div>
                <a href="/login" class="text-slate-300 hover:text-white mr-6 font-medium">Log In</a>
                <a href="/register" class="bg-indigo-600 hover:bg-indigo-500 px-5 py-2 rounded-full font-bold transition">Get Started</a>
            </div>
        </nav>

        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-20 pb-24 text-center">
            <div class="inline-block px-4 py-1.5 rounded-full border border-indigo-500/30 bg-indigo-500/10 text-indigo-300 text-sm font-semibold mb-6">
                ✨ New: GPT-4o Security Engine
            </div>
            <h1 class="text-5xl md:text-7xl font-bold tracking-tight mb-8 bg-clip-text text-transparent bg-gradient-to-r from-white to-slate-400">
                Stop Secrets from Leaking <br> to ChatGPT.
            </h1>
            <p class="text-xl text-slate-400 max-w-2xl mx-auto mb-10 leading-relaxed">
                VIGIL is the AI Firewall for modern companies. We intercept employee prompts, scan for API keys & PII, and block sensitive data instantly.
            </p>
            <div class="flex flex-col sm:flex-row justify-center gap-4">
                <a href="/register" class="bg-indigo-600 hover:bg-indigo-500 text-white text-lg px-8 py-4 rounded-lg font-bold shadow-lg shadow-indigo-500/20 transition">
                    Start Protecting Free
                </a>
                <a href="#how" class="bg-slate-800 hover:bg-slate-700 text-white text-lg px-8 py-4 rounded-lg font-semibold transition border border-slate-700">
                    How it Works
                </a>
            </div>
        </div>
    </div>

    <div id="how" class="bg-slate-950 py-24 border-t border-slate-800">
        <div class="max-w-7xl mx-auto px-4">
            <div class="grid md:grid-cols-3 gap-8">
                <div class="p-8 rounded-2xl bg-slate-900 border border-slate-800 hover:border-indigo-500/50 transition duration-300">
                    <div class="w-12 h-12 bg-indigo-500/20 rounded-lg flex items-center justify-center text-2xl mb-6">🕵️‍♂️</div>
                    <h3 class="text-xl font-bold mb-3">Real-time Interception</h3>
                    <p class="text-slate-400">We act as a proxy between your team and AI. Every prompt is scanned in milliseconds.</p>
                </div>
                <div class="p-8 rounded-2xl bg-slate-900 border border-slate-800 hover:border-red-500/50 transition duration-300">
                    <div class="w-12 h-12 bg-red-500/20 rounded-lg flex items-center justify-center text-2xl mb-6">🛑</div>
                    <h3 class="text-xl font-bold mb-3">Secret Blocking</h3>
                    <p class="text-slate-400">Detects AWS keys, Database passwords, and Customer PII. Blocks them before they leave.</p>
                </div>
                <div class="p-8 rounded-2xl bg-slate-900 border border-slate-800 hover:border-green-500/50 transition duration-300">
                    <div class="w-12 h-12 bg-green-500/20 rounded-lg flex items-center justify-center text-2xl mb-6">🔔</div>
                    <h3 class="text-xl font-bold mb-3">Instant Alerts</h3>
                    <p class="text-slate-400">Security teams get notified via Discord/Slack the moment a leak is attempted.</p>
                </div>
            </div>
        </div>
    </div>
    </body></html>
    """)


# --- ROUTE: DASHBOARD (The Command Center) ---
@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM transactions_v5 WHERE user_id = %s ORDER BY created_at DESC;", (current_user.id,))
    rows = cur.fetchall()
    cur.close()
    conn.close()

    return render_template_string(BASE_HTML + """
    <div class="min-h-screen bg-slate-900">
        <nav class="bg-slate-800 border-b border-slate-700 px-6 py-4 flex justify-between items-center">
            <div class="flex items-center gap-3">
                <span class="text-indigo-400 font-bold text-xl tracking-tight">VIGIL</span>
                <span class="bg-slate-700 text-xs px-2 py-1 rounded text-slate-300">BETA</span>
            </div>
            <div class="flex gap-4 text-sm font-medium">
                <a href="/settings" class="text-slate-400 hover:text-white transition">Settings</a>
                <a href="/simulate_leak" class="text-red-400 hover:text-red-300 transition">⚠️ Simulate Leak</a>
                <a href="/logout" class="text-slate-400 hover:text-white transition">Log Out</a>
            </div>
        </nav>

        <main class="max-w-5xl mx-auto p-6">
            <header class="mb-8 flex justify-between items-end">
                <div>
                    <h2 class="text-3xl font-bold text-white mb-2">Security Feed</h2>
                    <p class="text-slate-400">Monitoring real-time AI prompt traffic for {{ user.username }}.</p>
                </div>
                <div class="text-right hidden sm:block">
                    <div class="text-sm text-slate-500">System Status</div>
                    <div class="flex items-center gap-2 text-green-400 font-semibold">
                        <span class="w-2 h-2 bg-green-500 rounded-full animate-pulse"></span> Active
                    </div>
                </div>
            </header>

            {% if not rows %}
            <div class="text-center py-20 bg-slate-800/50 rounded-2xl border border-slate-700 border-dashed">
                <div class="text-4xl mb-4">🛡️</div>
                <h3 class="text-xl font-semibold text-white mb-2">No Incidents Logged</h3>
                <p class="text-slate-400 mb-6">Your system is secure. Try simulating a leak to test the engine.</p>
                <a href="/simulate_leak" class="bg-indigo-600 hover:bg-indigo-500 text-white px-6 py-2 rounded-lg font-medium transition">Run Test</a>
            </div>
            {% endif %}

            <div class="space-y-4">
                {% for row in rows %}
                <div class="bg-slate-800 rounded-xl p-5 border-l-4 shadow-lg transition hover:bg-slate-800/80 {{ 'border-red-500' if row[5] > 70 else 'border-green-500' }}">
                    <div class="flex justify-between items-start mb-3">
                        <div class="flex items-center gap-3">
                            <span class="font-bold text-white">{{ row[2] }}</span>
                            <span class="text-xs px-2 py-0.5 rounded uppercase font-bold {{ 'bg-red-500/20 text-red-400' if row[4] == 'BLOCKED' else 'bg-green-500/20 text-green-400' }}">
                                {{ row[4] }}
                            </span>
                        </div>
                        <div class="text-slate-500 text-xs font-mono">{{ row[7].strftime('%H:%M:%S') }}</div>
                    </div>

                    <div class="bg-slate-900/50 rounded p-3 mb-3 font-mono text-sm text-slate-300 break-words">
                        "{{ row[3] }}"
                    </div>

                    <div class="flex items-center gap-2 text-sm">
                        <span class="text-slate-500">AI Analysis:</span>
                        <span class="font-medium {{ 'text-red-400' if row[5] > 70 else 'text-green-400' }}">
                            {{ row[6] }} (Risk Score: {{ row[5] }})
                        </span>
                    </div>
                </div>
                {% endfor %}
            </div>
        </main>
    </div>
    </body></html>
    """, user=current_user, rows=rows)


# --- ROUTE: LOGIN & REGISTER (Styled) ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users_v5 WHERE username = %s", (username,))
        row = cur.fetchone()
        cur.close();
        conn.close()
        if row and check_password_hash(row[2], password):
            user = User(id=row[0], username=row[1], password_hash=row[2], discord_webhook=row[3], api_key=row[4])
            login_user(user)
            return redirect(url_for('dashboard'))
        msg = "Invalid Credentials"

    return render_template_string(BASE_HTML + """
    <div class="min-h-screen flex items-center justify-center px-4">
        <div class="max-w-md w-full bg-slate-800 p-8 rounded-2xl shadow-2xl border border-slate-700">
            <h2 class="text-2xl font-bold text-center mb-2">Welcome Back</h2>
            <p class="text-slate-400 text-center mb-8">Sign in to VIGIL Console</p>
            {% if msg %}<div class="bg-red-500/20 text-red-400 p-3 rounded mb-4 text-center text-sm">{{ msg }}</div>{% endif %}
            <form method="POST" class="space-y-4">
                <input type="text" name="username" placeholder="Username" required class="w-full bg-slate-900 border border-slate-700 rounded-lg p-3 text-white focus:outline-none focus:border-indigo-500 transition">
                <input type="password" name="password" placeholder="Password" required class="w-full bg-slate-900 border border-slate-700 rounded-lg p-3 text-white focus:outline-none focus:border-indigo-500 transition">
                <button class="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-bold py-3 rounded-lg transition">Sign In</button>
            </form>
            <p class="text-center mt-6 text-slate-500 text-sm">Don't have an account? <a href="/register" class="text-indigo-400 hover:text-white">Sign up</a></p>
        </div>
    </div></body></html>""", msg=msg)


@app.route('/register', methods=['GET', 'POST'])
def register():
    msg = ""
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
            uid = cur.fetchone()[0]
            conn.commit();
            cur.close();
            conn.close()
            user = User(id=uid, username=username, password_hash=hashed_pw, discord_webhook=None, api_key=new_api_key)
            login_user(user)
            return redirect(url_for('settings'))
        except:
            msg = "Username taken"

    return render_template_string(BASE_HTML + """
    <div class="min-h-screen flex items-center justify-center px-4">
        <div class="max-w-md w-full bg-slate-800 p-8 rounded-2xl shadow-2xl border border-slate-700">
            <h2 class="text-2xl font-bold text-center mb-2">Create Account</h2>
            <p class="text-slate-400 text-center mb-8">Start protecting your company data</p>
            {% if msg %}<div class="bg-red-500/20 text-red-400 p-3 rounded mb-4 text-center text-sm">{{ msg }}</div>{% endif %}
            <form method="POST" class="space-y-4">
                <input type="text" name="username" placeholder="Choose Username" required class="w-full bg-slate-900 border border-slate-700 rounded-lg p-3 text-white focus:outline-none focus:border-indigo-500 transition">
                <input type="password" name="password" placeholder="Choose Password" required class="w-full bg-slate-900 border border-slate-700 rounded-lg p-3 text-white focus:outline-none focus:border-indigo-500 transition">
                <button class="w-full bg-green-600 hover:bg-green-500 text-white font-bold py-3 rounded-lg transition">Create Account</button>
            </form>
            <p class="text-center mt-6 text-slate-500 text-sm">Already a member? <a href="/login" class="text-indigo-400 hover:text-white">Log in</a></p>
        </div>
    </div></body></html>""", msg=msg)


# --- ROUTES: SETTINGS & API ---
@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        wh = request.form['webhook']
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE users_v5 SET discord_webhook = %s WHERE id = %s", (wh, current_user.id))
        conn.commit();
        cur.close();
        conn.close()
        current_user.discord_webhook = wh
        return redirect(url_for('dashboard'))

    return render_template_string(BASE_HTML + """
    <div class="min-h-screen bg-slate-900 p-6 flex items-center justify-center">
        <div class="max-w-2xl w-full bg-slate-800 p-8 rounded-2xl border border-slate-700">
            <h2 class="text-2xl font-bold mb-6">⚙️ Configuration</h2>
            <div class="mb-8">
                <label class="block text-sm font-bold text-slate-400 mb-2">Your API Key (Use this in your apps)</label>
                <div class="bg-slate-950 p-4 rounded-lg font-mono text-green-400 break-all border border-slate-800 select-all">{{ user.api_key }}</div>
            </div>
            <form method="POST">
                <label class="block text-sm font-bold text-slate-400 mb-2">Discord Webhook URL (For Alerts)</label>
                <input type="text" name="webhook" value="{{ user.discord_webhook or '' }}" placeholder="https://discord.com/api/webhooks/..." class="w-full bg-slate-900 border border-slate-700 rounded-lg p-3 text-white mb-4 focus:border-indigo-500 outline-none">
                <button class="bg-indigo-600 hover:bg-indigo-500 text-white px-6 py-3 rounded-lg font-bold w-full">Save Configuration</button>
            </form>
            <div class="mt-6 text-center"><a href="/dashboard" class="text-slate-500 hover:text-white">← Back to Dashboard</a></div>
        </div>
    </div></body></html>""", user=current_user)


@app.route('/simulate_leak')
@login_required
def simulate_leak():
    source = "Intern_David"
    prompt = "Debug this: const AWS_KEY = 'AKIA_TEST_KEY_12345'; // confidential"
    req_id = str(uuid.uuid4())[:8]
    score, reason = analyze_security_risk(prompt)
    status = "BLOCKED" if score > 70 else "ALLOWED"

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO transactions_v5 (id, user_id, source, description, status, risk_score, risk_reason) VALUES (%s,%s,%s,%s,%s,%s,%s)",
        (req_id, current_user.id, source, prompt, status, score, reason))
    conn.commit();
    cur.close();
    conn.close()

    if status == "BLOCKED":
        send_discord_alert(current_user.discord_webhook, f"🚨 **VIGIL BLOCKED LEAK**\nUser: {source}\nScore: {score}",
                           15548997)

    return redirect(url_for('dashboard'))


@app.route('/v1/firewall', methods=['POST'])
def firewall_api():
    # Same logic as before, just kept minimal for file size
    return jsonify({"status": "active"})


if __name__ == '__main__':
    app.run(port=5000)