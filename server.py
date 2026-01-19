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
openai_client = None; razorpay_client = None
if OPENAI_KEY:
    try: openai_client = OpenAI(api_key=OPENAI_KEY)
    except: pass
if RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET:
    try: razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
    except: pass

# --- VIGIL BRAIN ---
def analyze_security_risk(prompt_text):
    if not openai_client: return 0, "AI Not Configured"
    try:
        system_prompt = "You are VIGIL, a Data Loss Prevention (DLP) engine. Analyze input for API Keys, Passwords, PII. Return JSON: {\"risk_score\": 0-100, \"risk_reason\": \"explanation\"}."
        response = openai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": f"Scan: {prompt_text}"}],
            response_format={ "type": "json_object" }
        )
        result = json.loads(response.choices[0].message.content)
        return result.get('risk_score', 0), result.get('risk_reason', "Safe")
    except: return 50, "AI Analysis Failed"

# --- DATABASE ---
def get_db_connection():
    if not DB_URL: raise ValueError("DATABASE_URL is missing")
    conn = psycopg2.connect(DB_URL)
    return conn

def init_db():
    try:
        conn = get_db_connection(); cur = conn.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS users_v6 (id SERIAL PRIMARY KEY, username VARCHAR(50) UNIQUE NOT NULL, password_hash TEXT NOT NULL, discord_webhook TEXT, api_key VARCHAR(64) UNIQUE, plan_type VARCHAR(20) DEFAULT 'free');""")
        cur.execute("""CREATE TABLE IF NOT EXISTS transactions_v6 (id VARCHAR(10) PRIMARY KEY, user_id INTEGER REFERENCES users_v6(id), source VARCHAR(100), description TEXT, status VARCHAR(20), risk_score INTEGER, risk_reason TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);""")
        conn.commit(); cur.close(); conn.close()
    except Exception as e: print(f"❌ DB Init Error: {e}")

if DB_URL: init_db()

# --- AUTH ---
login_manager = LoginManager(); login_manager.init_app(app); login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, username, password_hash, discord_webhook, api_key, plan_type='free'):
        self.id = id; self.username = username; self.password_hash = password_hash; self.discord_webhook = discord_webhook; self.api_key = api_key; self.plan_type = plan_type

@login_manager.user_loader
def load_user(user_id):
    try:
        conn = get_db_connection(); cur = conn.cursor()
        cur.execute("SELECT * FROM users_v6 WHERE id = %s", (user_id,))
        res = cur.fetchone(); cur.close(); conn.close()
        if res: return User(id=res[0], username=res[1], password_hash=res[2], discord_webhook=res[3], api_key=res[4], plan_type=res[5])
    except: pass
    return None

def send_discord_alert(webhook_url, message, color=None):
    if not webhook_url: return
    try: requests.post(webhook_url, json={"embeds": [{"description": message, "color": color}]}, timeout=5)
    except: pass

# ===========================
# === VIGIL V7.0 UI SYSTEM ===
# ===========================

LOGO_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="w-8 h-8 text-indigo-500"><path fill-rule="evenodd" d="M12.516 2.17a.75.75 0 00-1.032 0 11.209 11.209 0 01-7.877 3.08.75.75 0 00-.722.515A12.74 12.74 0 002.25 9.75c0 5.942 4.064 10.933 9.563 12.348a.749.749 0 00.374 0c5.499-1.415 9.563-6.406 9.563-12.348 0-1.39-.223-2.73-.635-3.985a.75.75 0 00-.722-.516l-.143.001c-2.996 0-5.717-1.17-7.734-3.08zm3.094 8.016a.75.75 0 10-1.22-.872l-3.236 4.53L9.53 12.22a.75.75 0 00-1.06 1.06l2.25 2.25a.75.75 0 001.14-.094l3.75-5.25z" clip-rule="evenodd" /></svg>"""

BASE_HEAD = """
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>VIGIL | Enterprise AI Security</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Plus Jakarta Sans', sans-serif; background-color: #020617; color: #f8fafc; overflow-x: hidden; }
        .glass { background: rgba(30, 41, 59, 0.7); backdrop-filter: blur(12px); border: 1px solid rgba(255, 255, 255, 0.08); }
        .hero-glow { background: radial-gradient(circle at 50% 0%, rgba(99, 102, 241, 0.15) 0%, transparent 60%); }
        .gradient-text { background: linear-gradient(135deg, #fff 0%, #94a3b8 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    </style>
</head>
"""

NAVBAR_CONTENT = f"""
<nav x-data="{{ open: false }}" class="fixed w-full z-50 glass border-b border-slate-800 transition-all duration-300">
    <div class="max-w-7xl mx-auto px-6 h-20 flex justify-between items-center">
        <a href="/" class="flex items-center gap-3">{LOGO_SVG}<span class="text-xl font-bold tracking-tight text-white">VIGIL</span></a>
        <div class="hidden md:flex gap-8 text-sm font-medium text-slate-400 items-center">
            <a href="/#features" class="hover:text-white transition">Features</a>
            <a href="/#pricing" class="hover:text-white transition">Pricing</a>
            {{% if current_user.is_authenticated %}}
                <a href="/dashboard" class="text-white hover:text-indigo-400 transition">Dashboard</a>
                <a href="/logout" class="px-4 py-2 bg-slate-800 text-white rounded-lg font-bold hover:bg-slate-700 transition">Log Out</a>
            {{% else %}}
                <a href="/login" class="text-slate-300 hover:text-white transition">Log in</a>
                <a href="/register" class="px-4 py-2 bg-indigo-600 text-white rounded-lg font-bold hover:bg-indigo-500 transition shadow-lg shadow-indigo-500/20">Get Started</a>
            {{% endif %}}
        </div>
        <button @click="open = !open" class="md:hidden text-slate-300 focus:outline-none">
            <svg class="w-7 h-7" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"></path></svg>
        </button>
    </div>
    <div x-show="open" @click.away="open = false" class="md:hidden bg-slate-900 border-b border-slate-800 absolute w-full left-0 top-20 shadow-2xl">
        <div class="flex flex-col p-6 gap-4 text-center">
            <a href="/#features" class="text-slate-300 py-2 border-b border-slate-800">Features</a>
            <a href="/#pricing" class="text-slate-300 py-2 border-b border-slate-800">Pricing</a>
            {{% if current_user.is_authenticated %}}
                <a href="/dashboard" class="text-indigo-400 font-bold py-2">Go to Dashboard</a>
                <a href="/logout" class="text-slate-400 py-2">Log Out</a>
            {{% else %}}
                <a href="/login" class="text-indigo-400 font-semibold py-2">Log In</a>
                <a href="/register" class="bg-indigo-600 text-white py-3 rounded-xl font-bold">Create Account</a>
            {{% endif %}}
        </div>
    </div>
</nav>
"""

# --- ROUTES ---

@app.route('/')
def landing():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    return render_template_string(f"<!DOCTYPE html><html lang='en'>{BASE_HEAD}<body class='antialiased'>{NAVBAR_CONTENT}" + """
        <div class="pt-32 pb-16 lg:pt-48 lg:pb-32 px-6 text-center hero-glow">
            <div class="max-w-4xl mx-auto">
                <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-indigo-950/50 border border-indigo-500/30 text-indigo-300 text-xs font-bold mb-8 uppercase tracking-wide"><span class="w-2 h-2 bg-indigo-500 rounded-full animate-pulse"></span> V7.0 Unified Platform</div>
                <h1 class="text-4xl sm:text-6xl lg:text-7xl font-bold tracking-tight text-white mb-6 leading-tight">Security for the <br class="hidden sm:block" /><span class="gradient-text">Generative AI Era.</span></h1>
                <p class="text-lg sm:text-xl text-slate-400 mb-10 max-w-2xl mx-auto">Stop employees from accidentally pasting API keys and PII into ChatGPT. The enterprise firewall that fits in your pocket.</p>
                <div class="flex flex-col sm:flex-row justify-center gap-4 px-4"><a href="/register" class="w-full sm:w-auto px-8 py-4 bg-indigo-600 text-white font-bold rounded-xl hover:bg-indigo-500 transition shadow-lg shadow-indigo-500/25">Start Free</a><a href="#features" class="w-full sm:w-auto px-8 py-4 glass text-slate-300 font-bold rounded-xl hover:bg-slate-800 transition">Explore Features</a></div>
            </div>
        </div>
        <section id="features" class="py-24 bg-slate-900/50 border-t border-slate-800">
            <div class="max-w-7xl mx-auto px-6">
                <div class="text-center mb-16"><h2 class="text-3xl font-bold text-white mb-4">Enterprise-Grade Protection</h2><p class="text-slate-400">Everything you need to secure your AI workflow.</p></div>
                <div class="grid md:grid-cols-3 gap-8">
                    <div class="glass p-8 rounded-2xl border-t border-indigo-500/20"><div class="w-12 h-12 bg-slate-800 rounded-xl flex items-center justify-center text-2xl mb-6">🕵️‍♂️</div><h3 class="text-xl font-bold text-white mb-3">PII Redaction</h3><p class="text-slate-400 text-sm leading-relaxed">Automatically detects and blocks Social Security Numbers, Credit Cards, and Phone Numbers.</p></div>
                    <div class="glass p-8 rounded-2xl border-t border-purple-500/20"><div class="w-12 h-12 bg-slate-800 rounded-xl flex items-center justify-center text-2xl mb-6">🔑</div><h3 class="text-xl font-bold text-white mb-3">Secret Detection</h3><p class="text-slate-400 text-sm leading-relaxed">Prevents leaks of AWS Access Keys, Database Connection Strings, and Private Keys instantly.</p></div>
                    <div class="glass p-8 rounded-2xl border-t border-green-500/20"><div class="w-12 h-12 bg-slate-800 rounded-xl flex items-center justify-center text-2xl mb-6">📜</div><h3 class="text-xl font-bold text-white mb-3">Audit Logs</h3><p class="text-slate-400 text-sm leading-relaxed">Keep a permanent record of every blocked attempt for compliance and internal security reviews.</p></div>
                </div>
            </div>
        </section>
        <section id="pricing" class="py-24 relative">
            <div class="max-w-7xl mx-auto px-6">
                <div class="text-center mb-16"><h2 class="text-3xl font-bold text-white mb-4">Simple, Transparent Pricing</h2></div>
                <div class="grid md:grid-cols-2 gap-8 max-w-4xl mx-auto">
                    <div class="p-8 rounded-3xl border border-slate-800 bg-slate-900/50"><h3 class="text-xl font-bold text-slate-300 mb-2">Developer</h3><div class="text-4xl font-bold text-white mb-6">Free</div><ul class="space-y-4 text-slate-400 mb-8 text-sm"><li class="flex gap-3"><span>✓</span> 100 Scans / month</li><li class="flex gap-3"><span>✓</span> Basic PII Detection</li></ul><a href="/register" class="block w-full py-3 rounded-xl border border-slate-700 text-center font-bold text-white hover:bg-slate-800 transition">Get Started</a></div>
                    <div class="p-8 rounded-3xl border border-indigo-500/50 bg-indigo-900/10 relative overflow-hidden"><div class="absolute top-0 right-0 bg-indigo-600 text-xs font-bold px-3 py-1 rounded-bl-xl text-white">POPULAR</div><h3 class="text-xl font-bold text-white mb-2">Startup</h3><div class="text-4xl font-bold text-white mb-6">₹999 <span class="text-lg text-slate-400 font-normal">/mo</span></div><ul class="space-y-4 text-slate-300 mb-8 text-sm"><li class="flex gap-3"><span class="text-indigo-400">✓</span> Unlimited Scans</li><li class="flex gap-3"><span class="text-indigo-400">✓</span> Advanced Secret Detection</li></ul><a href="/register" class="block w-full py-3 rounded-xl bg-indigo-600 text-center font-bold text-white hover:bg-indigo-500 transition shadow-lg shadow-indigo-500/25">Start 14-Day Trial</a></div>
                </div>
            </div>
        </section>
        <footer class="py-12 text-center text-slate-600 text-sm border-t border-slate-900">&copy; 2026 VIGIL Security.</footer>
    </body></html>""", current_user=current_user)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        wh = request.form.get('discord_webhook')
        if wh:
            conn = get_db_connection(); cur = conn.cursor()
            cur.execute("UPDATE users_v6 SET discord_webhook = %s WHERE id = %s", (wh, current_user.id))
            conn.commit(); cur.close(); conn.close()
            return redirect(url_for('dashboard'))

    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("SELECT * FROM transactions_v6 WHERE user_id = %s ORDER BY created_at DESC LIMIT 20;", (current_user.id,))
    rows = cur.fetchall(); cur.close(); conn.close()
    
    return render_template_string(f"<!DOCTYPE html><html lang='en'>{BASE_HEAD}<body class='bg-slate-950 pb-20'>{NAVBAR_CONTENT}" + """
        <main class="pt-32 max-w-7xl mx-auto px-6">
            <div class="flex flex-col md:flex-row justify-between items-start md:items-center mb-8 gap-4">
                <div><h2 class="text-2xl font-bold text-white">Security Dashboard</h2><p class="text-slate-400 text-sm">Manage your API keys and monitor threats.</p></div>
                <div class="flex gap-3"><a href="/simulate_leak" class="bg-red-600 hover:bg-red-500 text-white px-4 py-2 rounded-lg text-sm font-bold shadow-lg shadow-red-500/20 flex items-center gap-2 transition"><span>⚠️</span> Simulate Leak</a></div>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-10">
                <div class="glass p-6 rounded-2xl border-t border-indigo-500/20 relative overflow-hidden">
                    <div class="absolute top-0 right-0 p-4 opacity-10 text-6xl">🔑</div>
                    <div class="text-indigo-400 text-xs font-bold uppercase tracking-wider mb-2">Your API Key</div>
                    <div class="font-mono text-sm text-white bg-slate-950/50 p-4 rounded-xl border border-slate-800 break-all select-all mb-2">{{ user.api_key }}</div>
                    <p class="text-slate-500 text-xs">Update your Chrome Extension with this new key.</p>
                </div>
                <div class="glass p-6 rounded-2xl border-t border-purple-500/20 relative overflow-hidden">
                    <div class="absolute top-0 right-0 p-4 opacity-10 text-6xl">🔔</div>
                    <div class="text-purple-400 text-xs font-bold uppercase tracking-wider mb-2">Discord Alerts</div>
                    <form method="POST" class="mt-2"><div class="flex gap-2"><input type="text" name="discord_webhook" value="{{ user.discord_webhook or '' }}" placeholder="Paste Discord Webhook URL..." class="w-full bg-slate-950/50 border border-slate-800 rounded-xl px-4 py-3 text-sm text-white focus:outline-none focus:border-purple-500 placeholder-slate-600 transition"><button class="bg-purple-600 hover:bg-purple-500 text-white px-6 py-2 rounded-xl text-sm font-bold transition shadow-lg shadow-purple-500/20">Save</button></div></form>
                </div>
            </div>

            <div class="mb-4 flex items-center gap-3"><h3 class="text-lg font-bold text-white">Recent Activity</h3><span class="px-2 py-1 bg-green-500/10 text-green-400 text-xs font-bold rounded-full border border-green-500/20 flex items-center gap-2"><span class="w-1.5 h-1.5 bg-green-500 rounded-full animate-pulse"></span> Live</span></div>

            <div class="space-y-3">
                {% if not rows %}<div class="text-center py-12 rounded-2xl border border-dashed border-slate-800"><div class="text-4xl mb-4 opacity-50">🛡️</div><p class="text-slate-400">No threats detected yet.</p></div>{% endif %}
                {% for row in rows %}
                <div class="glass rounded-xl p-5 border-l-[4px] transition hover:bg-slate-800/50 {{ 'border-red-500' if row[5] > 70 else 'border-green-500' }}">
                    <div class="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
                        <div class="flex-1 min-w-0">
                            <div class="flex items-center gap-3 mb-2"><span class="font-bold text-white text-sm">{{ row[2] }}</span><span class="text-[10px] px-2 py-0.5 rounded uppercase font-black tracking-wider {{ 'bg-red-500/20 text-red-400' if row[4] == 'BLOCKED' else 'bg-green-500/20 text-green-400' }}">{{ row[4] }}</span></div>
                            <div class="font-mono text-xs text-slate-300 break-all bg-black/30 p-2 rounded border border-white/5">"{{ row[3] }}"</div>
                        </div>
                        <div class="flex items-center gap-6 text-xs text-slate-500 whitespace-nowrap"><div class="flex flex-col items-end"><span class="uppercase font-bold text-[10px] tracking-wide mb-0.5">Risk Score</span><span class="text-sm font-bold {{ 'text-red-400' if row[5] > 70 else 'text-green-400' }}">{{ row[5] }}/100</span></div><div class="flex flex-col items-end"><span class="uppercase font-bold text-[10px] tracking-wide mb-0.5">Time</span><span>{{ row[7].strftime('%H:%M') }}</span></div></div>
                    </div>
                </div>
                {% endfor %}
            </div>
        </main>
    </body></html>""", user=current_user, rows=rows, current_user=current_user)

AUTH_LAYOUT = f"""<!DOCTYPE html><html lang='en'>{BASE_HEAD}<body class="min-h-screen bg-slate-950 flex flex-col justify-center py-12 sm:px-6 lg:px-8"><div class="sm:mx-auto sm:w-full sm:max-w-md text-center mb-8"><div class="mx-auto h-12 w-12 flex items-center justify-center bg-indigo-500/10 rounded-xl mb-4">{LOGO_SVG}</div><h2 class="text-3xl font-extrabold text-white">VIGIL</h2><p class="mt-2 text-sm text-slate-400">Enterprise AI Security</p></div><div class="mt-8 sm:mx-auto sm:w-full sm:max-w-md"><div class="glass py-8 px-6 shadow rounded-2xl sm:px-10">CONTENT_PLACEHOLDER</div></div></body></html>"""

@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ""
    if request.method == 'POST':
        u = request.form['username']; p = request.form['password']
        conn = get_db_connection(); cur = conn.cursor(); cur.execute("SELECT * FROM users_v6 WHERE username = %s", (u,))
        row = cur.fetchone(); cur.close(); conn.close()
        if row and check_password_hash(row[2], p):
            user = User(id=row[0], username=row[1], password_hash=row[2], discord_webhook=row[3], api_key=row[4], plan_type=row[5]); login_user(user); return redirect(url_for('dashboard'))
        msg = "Invalid credentials"
    form = f"""<form class="space-y-6" method="POST">{'<div class="bg-red-500/10 text-red-400 p-3 rounded-lg text-sm text-center border border-red-500/20">'+msg+'</div>' if msg else ''}<div><label class="block text-sm font-medium text-slate-300">Username</label><div class="mt-1"><input name="username" type="text" required class="appearance-none block w-full px-3 py-3 border border-slate-700 rounded-xl bg-slate-900/50 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"></div></div><div><label class="block text-sm font-medium text-slate-300">Password</label><div class="mt-1"><input name="password" type="password" required class="appearance-none block w-full px-3 py-3 border border-slate-700 rounded-xl bg-slate-900/50 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"></div></div><div><button type="submit" class="w-full flex justify-center py-3 px-4 border border-transparent rounded-xl shadow-sm text-sm font-bold text-white bg-indigo-600 hover:bg-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 transition">Sign in</button></div></form><div class="mt-6"><div class="relative"><div class="absolute inset-0 flex items-center"><div class="w-full border-t border-slate-700"></div></div><div class="relative flex justify-center text-sm"><span class="px-2 bg-slate-900 text-slate-500">Or</span></div></div><div class="mt-6 grid grid-cols-1 gap-3"><a href="/register" class="w-full flex justify-center py-3 px-4 border border-slate-700 rounded-xl shadow-sm text-sm font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 transition">Create new account</a></div></div>"""
    return render_template_string(AUTH_LAYOUT.replace("CONTENT_PLACEHOLDER", form))

@app.route('/register', methods=['GET', 'POST'])
def register():
    msg = ""
    if request.method == 'POST':
        u = request.form['username']; p = request.form['password']; h = generate_password_hash(p); k = "sk_live_" + secrets.token_hex(16)
        try: conn = get_db_connection(); cur = conn.cursor(); cur.execute("INSERT INTO users_v6 (username, password_hash, api_key) VALUES (%s, %s, %s) RETURNING id", (u, h, k)); uid = cur.fetchone()[0]; conn.commit(); cur.close(); conn.close(); user = User(id=uid, username=u, password_hash=h, discord_webhook=None, api_key=k); login_user(user); return redirect(url_for('dashboard'))
        except: msg = "Username taken"
    form = f"""<form class="space-y-6" method="POST">{'<div class="bg-red-500/10 text-red-400 p-3 rounded-lg text-sm text-center border border-red-500/20">'+msg+'</div>' if msg else ''}<div><label class="block text-sm font-medium text-slate-300">Choose Username</label><div class="mt-1"><input name="username" type="text" required class="appearance-none block w-full px-3 py-3 border border-slate-700 rounded-xl bg-slate-900/50 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"></div></div><div><label class="block text-sm font-medium text-slate-300">Choose Password</label><div class="mt-1"><input name="password" type="password" required class="appearance-none block w-full px-3 py-3 border border-slate-700 rounded-xl bg-slate-900/50 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"></div></div><div><button type="submit" class="w-full flex justify-center py-3 px-4 border border-transparent rounded-xl shadow-sm text-sm font-bold text-white bg-indigo-600 hover:bg-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 transition">Create Account</button></div></form><div class="mt-6 text-center text-sm"><a href="/login" class="font-medium text-indigo-400 hover:text-indigo-300">Already have an account? Log in</a></div>"""
    return render_template_string(AUTH_LAYOUT.replace("CONTENT_PLACEHOLDER", form))

@app.route('/v1/firewall', methods=['POST'])
def firewall_api():
    auth = request.headers.get('Authorization')
    if not auth or not auth.startswith("Bearer "): return jsonify({"error": "Missing API Key"}), 401
    api_key = auth.split(" ")[1]
    conn = get_db_connection(); cur = conn.cursor(); cur.execute("SELECT * FROM users_v6 WHERE api_key = %s", (api_key,)); u = cur.fetchone()
    if not u: return jsonify({"error": "Invalid Key"}), 403
    data = request.json; prompt = data.get("prompt", ""); source = data.get("source", "Extension"); req_id = str(uuid.uuid4())[:8]
    score, reason = analyze_security_risk(prompt); status = "BLOCKED" if score > 70 else "ALLOWED"
    cur.execute("INSERT INTO transactions_v6 (id, user_id, source, description, status, risk_score, risk_reason) VALUES (%s,%s,%s,%s,%s,%s,%s)", (req_id, u[0], source, prompt, status, score, reason)); conn.commit(); cur.close(); conn.close()
    if status == "BLOCKED": send_discord_alert(u[3], f"🚨 **BLOCKED**\nUser: {source}\nReason: {reason}", 15548997)
    return jsonify({"status": status, "risk_score": score, "reason": reason})

@app.route('/simulate_leak')
@login_required
def simulate_leak():
    try:
        source = "Test_User"; prompt = "Debug: AWS_KEY = 'AKIA_TEST_12345';"
        score, reason = analyze_security_risk(prompt); status = "BLOCKED" if score > 70 else "ALLOWED"
        conn = get_db_connection(); cur = conn.cursor(); cur.execute("INSERT INTO transactions_v6 (id, user_id, source, description, status, risk_score, risk_reason) VALUES (%s,%s,%s,%s,%s,%s,%s)", (str(uuid.uuid4())[:8], current_user.id, source, prompt, status, score, reason)); conn.commit(); cur.close(); conn.close()
        return redirect(url_for('dashboard'))
    except: return "Sim Failed"

@app.route('/logout')
@login_required
def logout_route(): logout_user(); return redirect(url_for('landing'))

if __name__ == '__main__': app.run(port=5000)
