import os
import uuid
import json
import psycopg2
import requests
import secrets
import traceback
import razorpay
from flask import Flask, request, jsonify, render_template_string, redirect, url_for, send_file, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from openai import OpenAI
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
app.secret_key = os.environ.get('SECRET_KEY', 'vigil_secret_key_999')

# --- CONFIGURATION ---
DB_URL = os.environ.get('DATABASE_URL')
OPENAI_KEY = os.environ.get('OPENAI_API_KEY')
RAZORPAY_KEY_ID = os.environ.get('RAZORPAY_KEY_ID')
RAZORPAY_KEY_SECRET = os.environ.get('RAZORPAY_KEY_SECRET')

# --- CLIENTS ---
openai_client = None;
razorpay_client = None
if OPENAI_KEY:
    try:
        openai_client = OpenAI(api_key=OPENAI_KEY)
    except:
        pass
if RAZORPAY_KEY_ID:
    try:
        razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
    except:
        pass


# --- LOGIC ---
def analyze_security_risk(prompt_text):
    if not openai_client: return 0, "AI Not Configured"
    try:
        sys_prompt = "You are VIGIL DLP. Analyze input for API Keys, Passwords, PII. Return JSON: {\"risk_score\": 0-100, \"risk_reason\": \"explanation\"}."
        resp = openai_client.chat.completions.create(model="gpt-4o-mini",
                                                     messages=[{"role": "system", "content": sys_prompt},
                                                               {"role": "user", "content": f"Scan: {prompt_text}"}],
                                                     response_format={"type": "json_object"})
        res = json.loads(resp.choices[0].message.content)
        return res.get('risk_score', 0), res.get('risk_reason', "Safe")
    except:
        return 50, "AI Analysis Failed"


def get_db(): return psycopg2.connect(DB_URL)


# --- DATABASE INIT ---
if DB_URL:
    try:
        conn = get_db();
        cur = conn.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS users_v5
        (
            id
            SERIAL
            PRIMARY
            KEY,
            username
            VARCHAR
                       (
            50
                       ) UNIQUE, password_hash TEXT, discord_webhook TEXT, api_key VARCHAR
                       (
                           64
                       ) UNIQUE, plan_type VARCHAR
                       (
                           20
                       ) DEFAULT 'free');""")
        cur.execute("""CREATE TABLE IF NOT EXISTS transactions_v5
        (
            id
            VARCHAR
                       (
            10
                       ) PRIMARY KEY, user_id INTEGER, source VARCHAR
                       (
                           100
                       ), description TEXT, status VARCHAR
                       (
                           20
                       ), risk_score INTEGER, risk_reason TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);""")
        conn.commit();
        cur.close();
        conn.close()
    except:
        pass

# --- AUTH SETUP ---
login_manager = LoginManager();
login_manager.init_app(app);
login_manager.login_view = 'login'


class User(UserMixin):
    def __init__(self, id, username, password_hash, discord_webhook, api_key, plan_type):
        self.id = id;
        self.username = username;
        self.password_hash = password_hash;
        self.discord_webhook = discord_webhook;
        self.api_key = api_key;
        self.plan_type = plan_type


@login_manager.user_loader
def load_user(uid):
    try:
        conn = get_db();
        cur = conn.cursor();
        cur.execute("SELECT * FROM users_v5 WHERE id = %s", (uid,));
        row = cur.fetchone();
        cur.close();
        conn.close()
        if row: return User(row[0], row[1], row[2], row[3], row[4], row[5])
    except:
        pass
    return None


# --- UI TEMPLATES ---
HEAD = """
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VIGIL | The AI Firewall</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Plus Jakarta Sans', sans-serif; background: #0B1120; color: #fff; scroll-behavior: smooth; }
        .glass { background: rgba(30, 41, 59, 0.4); backdrop-filter: blur(10px); border: 1px solid rgba(255, 255, 255, 0.08); }
        .text-gradient { background: linear-gradient(to right, #818cf8, #c084fc); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .step-card:hover { border-color: #6366f1; transform: translateY(-2px); transition: all 0.3s; }
    </style>
</head>
"""

NAVBAR = """
<nav x-data="{ open: false }" class="fixed w-full z-50 glass border-b border-white/5 bg-[#0B1120]/80">
    <div class="max-w-7xl mx-auto px-6 h-20 flex justify-between items-center">
        <a href="/" class="flex items-center gap-2">
            <div class="w-8 h-8 bg-indigo-600 rounded flex items-center justify-center font-bold">V</div>
            <span class="font-bold text-xl tracking-tight">VIGIL</span>
        </a>
        <div class="hidden md:flex items-center gap-8 text-sm font-medium text-slate-400">
            <a href="/#how-it-works" class="hover:text-white transition">How it Works</a>
            <a href="/#features" class="hover:text-white transition">Features</a>
            <div class="h-4 w-px bg-slate-700"></div>
            {% if current_user.is_authenticated %}
                <a href="/dashboard" class="text-white hover:text-indigo-400">Dashboard</a>
            {% else %}
                <a href="/login" class="hover:text-white">Sign In</a>
                <a href="/register" class="bg-white text-slate-900 px-4 py-2 rounded-lg font-bold hover:bg-slate-200 transition">Get Started</a>
            {% endif %}
        </div>
        <button @click="open = !open" class="md:hidden text-slate-300"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"></path></svg></button>
    </div>
    <div x-show="open" class="md:hidden glass border-b border-white/5">
        <div class="flex flex-col p-4 gap-4 text-center text-sm">
            <a href="/#how-it-works" class="text-slate-300 py-2">How it Works</a>
            <a href="/dashboard" class="text-indigo-400 font-bold py-2">Dashboard</a>
        </div>
    </div>
</nav>
"""


# --- ROUTES ---

@app.route('/')
def landing():
    return render_template_string("<!DOCTYPE html><html>" + HEAD + """
    <body>
        """ + NAVBAR + """

        <section class="pt-40 pb-20 px-6 text-center relative overflow-hidden">
            <div class="absolute top-0 left-1/2 -translate-x-1/2 w-[600px] h-[600px] bg-indigo-600/20 rounded-full blur-[120px] -z-10"></div>
            <div class="max-w-4xl mx-auto">
                <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-indigo-500/10 border border-indigo-500/20 text-indigo-300 text-xs font-bold mb-8 uppercase tracking-wide">
                    <span class="w-2 h-2 bg-indigo-500 rounded-full animate-pulse"></span> v1.0 Public Beta
                </div>
                <h1 class="text-5xl md:text-7xl font-bold mb-6 tracking-tight leading-tight">
                    Security for the <br/><span class="text-gradient">Generative AI Era.</span>
                </h1>
                <p class="text-lg text-slate-400 mb-10 max-w-2xl mx-auto leading-relaxed">
                    Prevent employees from accidentally pasting API keys, customer data, and passwords into ChatGPT, Claude, and Gemini.
                </p>
                <div class="flex flex-col sm:flex-row justify-center gap-4">
                    <a href="#download" class="px-8 py-4 bg-indigo-600 hover:bg-indigo-500 text-white font-bold rounded-xl transition shadow-lg shadow-indigo-500/25 flex items-center justify-center gap-2">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"></path></svg>
                        Download Extension
                    </a>
                    <a href="/register" class="px-8 py-4 glass hover:bg-white/5 text-white font-bold rounded-xl transition">Create Account</a>
                </div>
            </div>
        </section>

        <section id="download" class="py-20 bg-slate-900/50 border-y border-white/5">
            <div class="max-w-6xl mx-auto px-6">
                <div class="text-center mb-16">
                    <h2 class="text-3xl font-bold mb-4">How to Install</h2>
                    <p class="text-slate-400">Get up and running in less than 2 minutes.</p>
                </div>

                <div class="grid md:grid-cols-4 gap-6">
                    <div class="glass step-card p-6 rounded-2xl relative">
                        <div class="absolute -top-4 -left-4 w-8 h-8 bg-indigo-600 rounded-lg flex items-center justify-center font-bold text-white shadow-lg">1</div>
                        <h3 class="font-bold text-white mb-2">Download</h3>
                        <p class="text-slate-400 text-sm mb-4">Get the latest extension package (ZIP).</p>
                        <a href="/download_extension" class="text-xs bg-slate-800 hover:bg-indigo-600 px-3 py-2 rounded text-white transition">Download ZIP</a>
                    </div>
                    <div class="glass step-card p-6 rounded-2xl relative">
                        <div class="absolute -top-4 -left-4 w-8 h-8 bg-slate-700 rounded-lg flex items-center justify-center font-bold text-white shadow-lg">2</div>
                        <h3 class="font-bold text-white mb-2">Unzip</h3>
                        <p class="text-slate-400 text-sm">Extract the <code>vigil-beta.zip</code> file to a folder on your computer.</p>
                    </div>
                    <div class="glass step-card p-6 rounded-2xl relative">
                        <div class="absolute -top-4 -left-4 w-8 h-8 bg-slate-700 rounded-lg flex items-center justify-center font-bold text-white shadow-lg">3</div>
                        <h3 class="font-bold text-white mb-2">Load in Chrome</h3>
                        <p class="text-slate-400 text-sm">Go to <code>chrome://extensions</code>, turn on "Developer Mode", and click "Load Unpacked".</p>
                    </div>
                    <div class="glass step-card p-6 rounded-2xl relative">
                        <div class="absolute -top-4 -left-4 w-8 h-8 bg-slate-700 rounded-lg flex items-center justify-center font-bold text-white shadow-lg">4</div>
                        <h3 class="font-bold text-white mb-2">Connect</h3>
                        <p class="text-slate-400 text-sm">Click the VIGIL icon in your toolbar and paste your API Key from the Dashboard.</p>
                    </div>
                </div>
            </div>
        </section>

        <section id="features" class="py-24 px-6">
            <div class="max-w-6xl mx-auto grid md:grid-cols-3 gap-8">
                <div class="p-8 rounded-3xl bg-slate-800/20 border border-white/5">
                    <div class="text-3xl mb-4">🛡️</div>
                    <h3 class="text-xl font-bold text-white mb-2">Real-time Blocking</h3>
                    <p class="text-slate-400 text-sm">Intercepts pastes instantly. If it contains a secret, it never reaches ChatGPT.</p>
                </div>
                <div class="p-8 rounded-3xl bg-slate-800/20 border border-white/5">
                    <div class="text-3xl mb-4">⚡</div>
                    <h3 class="text-xl font-bold text-white mb-2">Low Latency</h3>
                    <p class="text-slate-400 text-sm">Built on Python Flask & OpenAI. Analysis takes milliseconds.</p>
                </div>
                <div class="p-8 rounded-3xl bg-slate-800/20 border border-white/5">
                    <div class="text-3xl mb-4">📝</div>
                    <h3 class="text-xl font-bold text-white mb-2">Audit Logs</h3>
                    <p class="text-slate-400 text-sm">Admins can see who tried to leak data, when, and what the risk score was.</p>
                </div>
            </div>
        </section>

        <footer class="py-12 text-center text-slate-600 text-sm border-t border-slate-900">
            &copy; 2026 VIGIL Security.
        </footer>
    </body>
    </html>
    """)


# --- FILE SERVING ---
@app.route('/download_extension')
def download_extension():
    # Looks for 'vigil-beta.zip' in the same folder as server.py
    try:
        return send_file('vigil-beta.zip', as_attachment=True)
    except:
        return "File not found. Please upload 'vigil-beta.zip' to your Render repository."


# --- API ---
@app.route('/v1/firewall', methods=['POST'])
def firewall_api():
    key = request.headers.get('Authorization', '').replace('Bearer ', '')
    conn = get_db();
    cur = conn.cursor();
    cur.execute("SELECT id, discord_webhook FROM users_v5 WHERE api_key = %s", (key,));
    user = cur.fetchone()
    if not user: return jsonify({"error": "Invalid Key"}), 403

    data = request.json
    score, reason = analyze_security_risk(data.get("prompt", ""))
    status = "BLOCKED" if score > 70 else "ALLOWED"

    cur.execute(
        "INSERT INTO transactions_v5 (id, user_id, source, description, status, risk_score, risk_reason) VALUES (%s,%s,%s,%s,%s,%s,%s)",
        (str(uuid.uuid4())[:8], user[0], data.get("source"), data.get("prompt"), status, score, reason))
    conn.commit();
    cur.close();
    conn.close()

    return jsonify({"status": status, "risk_score": score, "reason": reason})


# --- AUTH & DASHBOARD ROUTES ---
@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db();
    cur = conn.cursor();
    cur.execute("SELECT * FROM transactions_v5 WHERE user_id = %s ORDER BY created_at DESC LIMIT 20",
                (current_user.id,));
    rows = cur.fetchall();
    cur.close();
    conn.close()
    return render_template_string(
        "<!DOCTYPE html><html>" + HEAD + """<body>""" + NAVBAR + """<div class="max-w-6xl mx-auto p-6 mt-12"><h2 class="text-2xl font-bold mb-6">Security Events</h2><div class="space-y-4">{% for row in rows %}<div class="glass p-4 rounded-xl border-l-4 {{ 'border-red-500' if row[4] == 'BLOCKED' else 'border-green-500' }}"><div class="flex justify-between text-sm mb-2"><span class="font-bold text-white">{{ row[2] }}</span><span class="{{ 'text-red-400' if row[4] == 'BLOCKED' else 'text-green-400' }} font-bold">{{ row[4] }}</span></div><div class="font-mono text-xs bg-black/30 p-2 rounded text-slate-300 truncate">{{ row[3] }}</div><div class="mt-2 text-xs text-slate-500">{{ row[6] }} (Score: {{ row[5] }})</div></div>{% endfor %}</div></div></body></html>""",
        rows=rows, current_user=current_user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        conn = get_db();
        cur = conn.cursor();
        cur.execute("SELECT * FROM users_v5 WHERE username = %s", (request.form['username'],));
        row = cur.fetchone();
        cur.close();
        conn.close()
        if row and check_password_hash(row[2], request.form['password']): login_user(
            User(row[0], row[1], row[2], row[3], row[4], row[5])); return redirect(url_for('dashboard'))
    return render_template_string(
        "<!DOCTYPE html><html>" + HEAD + """<body class="flex items-center justify-center min-h-screen">""" + NAVBAR + """<div class="glass p-8 rounded-2xl w-full max-w-md mt-20"><h2 class="text-2xl font-bold mb-6 text-center">Login</h2><form method="POST" class="space-y-4"><input name="username" placeholder="Username" class="w-full bg-slate-900 border border-slate-700 p-3 rounded-lg"><input type="password" name="password" placeholder="Password" class="w-full bg-slate-900 border border-slate-700 p-3 rounded-lg"><button class="w-full bg-indigo-600 py-3 rounded-lg font-bold hover:bg-indigo-500">Sign In</button></form><div class="mt-4 text-center text-sm"><a href="/register" class="text-indigo-400">Create Account</a></div></div></body></html>""",
        current_user=current_user)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            conn = get_db();
            cur = conn.cursor();
            cur.execute("INSERT INTO users_v5 (username, password_hash, api_key) VALUES (%s, %s, %s) RETURNING id",
                        (request.form['username'], generate_password_hash(request.form['password']),
                         "sk_live_" + secrets.token_hex(16)));
            uid = cur.fetchone()[0];
            conn.commit();
            conn.close()
            login_user(User(uid, request.form['username'], "", "", "", "free"));
            return redirect(url_for('dashboard'))
        except:
            pass
    return render_template_string(
        "<!DOCTYPE html><html>" + HEAD + """<body class="flex items-center justify-center min-h-screen">""" + NAVBAR + """<div class="glass p-8 rounded-2xl w-full max-w-md mt-20"><h2 class="text-2xl font-bold mb-6 text-center">Start Free</h2><form method="POST" class="space-y-4"><input name="username" placeholder="Username" class="w-full bg-slate-900 border border-slate-700 p-3 rounded-lg"><input type="password" name="password" placeholder="Password" class="w-full bg-slate-900 border border-slate-700 p-3 rounded-lg"><button class="w-full bg-indigo-600 py-3 rounded-lg font-bold hover:bg-indigo-500">Create Account</button></form></div></body></html>""",
        current_user=current_user)


@app.route('/logout')
def logout(): logout_user(); return redirect(url_for('landing'))


if __name__ == '__main__': app.run(port=5000)