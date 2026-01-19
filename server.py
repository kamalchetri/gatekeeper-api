import os
import uuid
import json
import psycopg2
import requests
import secrets
import traceback
import razorpay
from flask import Flask, request, jsonify, render_template_string, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from openai import OpenAI
from flask_cors import CORS  # <--- THIS IS THE MISSING KEY

app = Flask(__name__)
CORS(app) # <--- THIS ALLOWS YOUR EXTENSION TO CONNECT
app.secret_key = os.environ.get('SECRET_KEY', 'vigil_secret_key_999')

# --- CONFIGURATION ---
DB_URL = os.environ.get('DATABASE_URL')
OPENAI_KEY = os.environ.get('OPENAI_API_KEY')
RAZORPAY_KEY_ID = os.environ.get('RAZORPAY_KEY_ID')
RAZORPAY_KEY_SECRET = os.environ.get('RAZORPAY_KEY_SECRET')

# --- CLIENTS ---
openai_client = None
razorpay_client = None

if OPENAI_KEY:
    try: openai_client = OpenAI(api_key=OPENAI_KEY)
    except: print("⚠️ OpenAI Key configuration issue")

if RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET:
    try: razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
    except: print("⚠️ Razorpay configuration issue")

# --- VIGIL BRAIN ---
def analyze_security_risk(prompt_text):
    if not openai_client: return 0, "AI Not Configured"
    try:
        system_prompt = "You are VIGIL, a Data Loss Prevention (DLP) engine. Analyze input for API Keys, Passwords, PII. Return JSON: {\"risk_score\": 0-100, \"risk_reason\": \"explanation\"}."
        response = openai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Scan: {prompt_text}"}
            ],
            response_format={ "type": "json_object" }
        )
        result = json.loads(response.choices[0].message.content)
        return result.get('risk_score', 0), result.get('risk_reason', "Safe")
    except:
        return 50, "AI Analysis Failed"

# --- DATABASE ---
def get_db_connection():
    if not DB_URL: raise ValueError("DATABASE_URL is missing")
    conn = psycopg2.connect(DB_URL)
    return conn

def init_db():
    try:
        conn = get_db_connection(); cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users_v5 (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                discord_webhook TEXT,
                api_key VARCHAR(64) UNIQUE,
                plan_type VARCHAR(20) DEFAULT 'free'
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS transactions_v5 (
                id VARCHAR(10) PRIMARY KEY,
                user_id INTEGER REFERENCES users_v5(id), 
                source VARCHAR(100),
                description TEXT,
                status VARCHAR(20),
                risk_score INTEGER,
                risk_reason TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        conn.commit(); cur.close(); conn.close()
    except Exception as e: print(f"❌ DB Init Error: {e}")

if DB_URL: init_db()

# --- AUTH ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, username, password_hash, discord_webhook, api_key, plan_type='free'):
        self.id = id; self.username = username; self.password_hash = password_hash; self.discord_webhook = discord_webhook; self.api_key = api_key; self.plan_type = plan_type

@login_manager.user_loader
def load_user(user_id):
    try:
        conn = get_db_connection(); cur = conn.cursor()
        cur.execute("SELECT * FROM users_v5 WHERE id = %s", (user_id,))
        res = cur.fetchone(); cur.close(); conn.close()
        if res: return User(id=res[0], username=res[1], password_hash=res[2], discord_webhook=res[3], api_key=res[4], plan_type=res[5])
    except: pass
    return None

def send_discord_alert(webhook_url, message, color=None):
    if not webhook_url: return
    try: requests.post(webhook_url, json={"embeds": [{"description": message, "color": color}]}, timeout=5)
    except: pass

# --- UI ASSETS ---
BASE_HEAD = """
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>VIGIL | Enterprise AI Security</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
    <script src="https://checkout.razorpay.com/v1/checkout.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Plus Jakarta Sans', sans-serif; background-color: #020617; color: #f8fafc; overflow-x: hidden; }
        .glass { background: rgba(30, 41, 59, 0.6); backdrop-filter: blur(12px); border: 1px solid rgba(255, 255, 255, 0.05); }
        .hero-glow { background: radial-gradient(circle at 50% 0%, rgba(99, 102, 241, 0.15) 0%, transparent 60%); }
        .gradient-text { background: linear-gradient(135deg, #fff 0%, #94a3b8 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    </style>
</head>
"""

# --- ROUTES ---

@app.route('/')
def landing():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    return render_template_string("<!DOCTYPE html><html lang='en'>" + BASE_HEAD + """
    <body class="antialiased">
        <nav class="fixed w-full z-50 glass border-b border-slate-800"><div class="max-w-7xl mx-auto px-6 h-20 flex justify-between items-center"><a href="/" class="flex items-center gap-3"><div class="w-9 h-9 bg-indigo-600 rounded-lg flex items-center justify-center font-bold text-white">V</div><span class="text-xl font-bold tracking-tight text-white">VIGIL</span></a><div class="flex gap-4"><a href="/login" class="px-5 py-2.5 text-sm font-medium text-slate-300">Log in</a><a href="/register" class="px-5 py-2.5 text-sm font-bold bg-white text-slate-950 rounded-lg">Get Started</a></div></div></nav>
        <div class="pt-48 pb-32 px-6 text-center hero-glow"><h1 class="text-5xl lg:text-7xl font-bold mb-6">The Firewall for <br><span class="gradient-text">AI.</span></h1><p class="text-xl text-slate-400 mb-10">Stop data leaks in ChatGPT & Claude.</p><a href="/register" class="px-8 py-4 bg-indigo-600 text-white font-bold rounded-xl">Start Free</a></div>
    </body></html>
    """)

# --- PAYMENT ROUTES ---
@app.route('/create_order', methods=['POST'])
@login_required
def create_order():
    if not razorpay_client: return jsonify({"error": "Payment Gateway Error"}), 500
    try:
        order = razorpay_client.order.create({"amount": 99900, "currency": "INR", "receipt": f"rcpt_{current_user.id}"})
        return jsonify(order)
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route('/verify_payment', methods=['POST'])
@login_required
def verify_payment():
    data = request.json
    try:
        razorpay_client.utility.verify_payment_signature({
            'razorpay_order_id': data['razorpay_order_id'],
            'razorpay_payment_id': data['razorpay_payment_id'],
            'razorpay_signature': data['razorpay_signature']
        })
        conn = get_db_connection(); cur = conn.cursor()
        cur.execute("UPDATE users_v5 SET plan_type = 'startup' WHERE id = %s", (current_user.id,))
        conn.commit(); cur.close(); conn.close()
        return jsonify({"status": "success"})
    except: return jsonify({"status": "failed"}), 400

# --- API ENDPOINT (Now with CORS) ---
@app.route('/v1/firewall', methods=['POST'])
def firewall_api():
    # 1. Validate API Key
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith("Bearer "): return jsonify({"error": "Missing API Key"}), 401
    api_key = auth_header.split(" ")[1]
    
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("SELECT * FROM users_v5 WHERE api_key = %s", (api_key,))
    user_row = cur.fetchone()
    
    if not user_row: return jsonify({"error": "Invalid API Key"}), 403
    user_id = user_row[0]; webhook = user_row[3]

    # 2. Analyze
    data = request.json
    prompt = data.get("prompt", "")
    source = data.get("source", "Browser Extension")
    req_id = str(uuid.uuid4())[:8]
    
    score, reason = analyze_security_risk(prompt)
    status = "BLOCKED" if score > 70 else "ALLOWED"
    
    # 3. Log
    cur.execute("INSERT INTO transactions_v5 (id, user_id, source, description, status, risk_score, risk_reason) VALUES (%s,%s,%s,%s,%s,%s,%s)", (req_id, user_id, source, prompt, status, score, reason))
    conn.commit(); cur.close(); conn.close()
    
    # 4. Alert
    if status == "BLOCKED": send_discord_alert(webhook, f"🚨 **VIGIL BLOCKED LEAK**\nUser: {source}\nReason: {reason}", 15548997)
    
    return jsonify({"status": status, "risk_score": score, "reason": reason})

# --- DASHBOARD & AUTH (Same as before, minimized for space) ---
@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("SELECT * FROM transactions_v5 WHERE user_id = %s ORDER BY created_at DESC LIMIT 20;", (current_user.id,))
    rows = cur.fetchall(); cur.close(); conn.close()
    return render_template_string("<!DOCTYPE html><html lang='en'>" + BASE_HEAD + """<body class="bg-slate-950 pb-20"><nav class="glass border-b border-slate-800 px-4 h-16 flex justify-between items-center"><div class="font-bold text-white">VIGIL DASHBOARD</div><div class="flex gap-4 text-sm"><a href="/logout" class="text-slate-400">Logout</a></div></nav><main class="max-w-5xl mx-auto p-4 mt-8"><div class="flex justify-between items-end mb-6"><h2 class="text-xl font-bold text-white">Activity Feed</h2></div><div class="space-y-4">{% for row in rows %}<div class="glass rounded-xl p-5 border-l-[4px] {{ 'border-red-500' if row[5] > 70 else 'border-green-500' }}"><div class="flex justify-between mb-2"><span class="font-bold text-white text-sm">{{ row[2] }}</span><span class="text-[10px] px-2 py-0.5 rounded uppercase font-black {{ 'bg-red-500/20 text-red-400' if row[4] == 'BLOCKED' else 'bg-green-500/20 text-green-400' }}">{{ row[4] }}</span></div><div class="bg-black/40 rounded p-3 mb-2 font-mono text-xs text-slate-300 break-all">"{{ row[3] }}"</div><div class="text-xs text-slate-500">Risk Score: {{ row[5] }} ({{ row[6] }})</div></div>{% endfor %}</div></main></body></html>""", rows=rows)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u = request.form['username']; p = request.form['password']
        conn = get_db_connection(); cur = conn.cursor(); cur.execute("SELECT * FROM users_v5 WHERE username = %s", (u,)); row = cur.fetchone(); cur.close(); conn.close()
        if row and check_password_hash(row[2], p): user = User(id=row[0], username=row[1], password_hash=row[2], discord_webhook=row[3], api_key=row[4], plan_type=row[5]); login_user(user); return redirect(url_for('dashboard'))
    return render_template_string("<!DOCTYPE html><html lang='en'>" + BASE_HEAD + """<body class="bg-slate-950 flex items-center justify-center min-h-screen"><div class="glass p-8 rounded-2xl w-full max-w-md"><h2 class="text-2xl font-bold text-white mb-6">Login</h2><form method="POST" class="space-y-4"><input type="text" name="username" placeholder="Username" required class="w-full bg-slate-900 border border-slate-700 rounded-xl p-4 text-white"><input type="password" name="password" placeholder="Password" required class="w-full bg-slate-900 border border-slate-700 rounded-xl p-4 text-white"><button class="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-bold py-4 rounded-xl">Sign In</button></form><div class="mt-4 text-center"><a href="/register" class="text-indigo-400 text-sm">Create Account</a></div></div></body></html>""")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        u = request.form['username']; p = request.form['password']; h = generate_password_hash(p); k = "sk_live_" + secrets.token_hex(16)
        try: conn = get_db_connection(); cur = conn.cursor(); cur.execute("INSERT INTO users_v5 (username, password_hash, api_key) VALUES (%s, %s, %s) RETURNING id", (u, h, k)); uid = cur.fetchone()[0]; conn.commit(); cur.close(); conn.close(); user = User(id=uid, username=u, password_hash=h, discord_webhook=None, api_key=k); login_user(user); return redirect(url_for('dashboard'))
        except: pass
    return render_template_string("<!DOCTYPE html><html lang='en'>" + BASE_HEAD + """<body class="bg-slate-950 flex items-center justify-center min-h-screen"><div class="glass p-8 rounded-2xl w-full max-w-md"><h2 class="text-2xl font-bold text-white mb-6">Register</h2><form method="POST" class="space-y-4"><input type="text" name="username" placeholder="Username" required class="w-full bg-slate-900 border border-slate-700 rounded-xl p-4 text-white"><input type="password" name="password" placeholder="Password" required class="w-full bg-slate-900 border border-slate-700 rounded-xl p-4 text-white"><button class="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-bold py-4 rounded-xl">Create Account</button></form><div class="mt-4 text-center"><a href="/login" class="text-indigo-400 text-sm">Login</a></div></div></body></html>""")

@app.route('/logout')
@login_required
def logout_route(): logout_user(); return redirect(url_for('landing'))

@app.route('/settings')
@login_required
def settings(): return render_template_string("<!DOCTYPE html><html lang='en'>" + BASE_HEAD + """<body class="bg-slate-950 flex items-center justify-center min-h-screen"><div class="glass p-8 rounded-2xl"><h2 class="text-2xl font-bold text-white mb-4">API Key</h2><div class="bg-black p-4 rounded text-green-400 font-mono mb-4">{{ user.api_key }}</div><a href="/dashboard" class="text-slate-400">Back</a></div></body></html>""", user=current_user)

if __name__ == '__main__': app.run(port=5000)
