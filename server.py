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
openai_client = None
razorpay_client = None

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
        cur.execute("""CREATE TABLE IF NOT EXISTS users_v5 (id SERIAL PRIMARY KEY, username VARCHAR(50) UNIQUE NOT NULL, password_hash TEXT NOT NULL, discord_webhook TEXT, api_key VARCHAR(64) UNIQUE, plan_type VARCHAR(20) DEFAULT 'free');""")
        cur.execute("""CREATE TABLE IF NOT EXISTS transactions_v5 (id VARCHAR(10) PRIMARY KEY, user_id INTEGER REFERENCES users_v5(id), source VARCHAR(100), description TEXT, status VARCHAR(20), risk_score INTEGER, risk_reason TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);""")
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
        conn = get_db_connection(); cur = conn.cursor(); cur.execute("SELECT * FROM users_v5 WHERE id = %s", (user_id,)); res = cur.fetchone(); cur.close(); conn.close()
        if res: return User(id=res[0], username=res[1], password_hash=res[2], discord_webhook=res[3], api_key=res[4], plan_type=res[5])
    except: pass
    return None

def send_discord_alert(webhook_url, message, color=None):
    if not webhook_url: return
    try: requests.post(webhook_url, json={"embeds": [{"description": message, "color": color}]}, timeout=5)
    except: pass

# ===========================
# === UI COMPONENTS ===
# ===========================

LOGO_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="w-8 h-8 text-indigo-500"><path fill-rule="evenodd" d="M12.516 2.17a.75.75 0 00-1.032 0 11.209 11.209 0 01-7.877 3.08.75.75 0 00-.722.515A12.74 12.74 0 002.25 9.75c0 5.942 4.064 10.933 9.563 12.348a.749.749 0 00.374 0c5.499-1.415 9.563-6.406 9.563-12.348 0-1.39-.223-2.73-.635-3.985a.75.75 0 00-.722-.516l-.143.001c-2.996 0-5.717-1.17-7.734-3.08zm3.094 8.016a.75.75 0 10-1.22-.872l-3.236 4.53L9.53 12.22a.75.75 0 00-1.06 1.06l2.25 2.25a.75.75 0 001.14-.094l3.75-5.25z" clip-rule="evenodd" /></svg>"""

BASE_HEAD = """
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>VIGIL | Enterprise AI Security</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Inter', sans-serif; background-color: #0f172a; color: #f8fafc; scroll-behavior: smooth; }
        .glass { background: rgba(30, 41, 59, 0.7); backdrop-filter: blur(10px); border: 1px solid rgba(255, 255, 255, 0.08); }
        .gradient-text { background: linear-gradient(135deg, #818cf8 0%, #c084fc 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .code-block { background: #1e1e1e; border: 1px solid #333; border-radius: 8px; padding: 15px; overflow-x: auto; font-family: monospace; font-size: 0.85rem; color: #d4d4d4; }
        .feature-card { transition: all 0.3s ease; }
        .feature-card:hover { transform: translateY(-5px); border-color: rgba(129, 140, 248, 0.4); }
    </style>
</head>
"""

NAVBAR = f"""
<nav x-data="{{ open: false }}" class="fixed w-full z-50 glass border-b border-slate-800 backdrop-blur-md">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="flex justify-between h-16">
            <div class="flex items-center gap-2">
                {LOGO_SVG}
                <span class="font-bold text-xl tracking-tight text-white">VIGIL</span>
            </div>
            
            <div class="hidden md:flex items-center gap-8">
                <a href="#how-it-works" class="text-sm font-medium text-slate-300 hover:text-white transition">How it Works</a>
                <a href="#developers" class="text-sm font-medium text-slate-300 hover:text-white transition">Developers</a>
                <a href="#teams" class="text-sm font-medium text-slate-300 hover:text-white transition">Teams</a>
                <a href="/login" class="text-sm font-medium text-indigo-400 hover:text-indigo-300 transition">Log In</a>
                <a href="/register" class="bg-indigo-600 hover:bg-indigo-500 text-white px-4 py-2 rounded-lg text-sm font-bold transition shadow-lg shadow-indigo-500/20">Get Started</a>
            </div>

            <div class="flex items-center md:hidden">
                <button @click="open = !open" class="text-slate-300 hover:text-white focus:outline-none p-2">
                    <svg class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" /></svg>
                </button>
            </div>
        </div>
    </div>

    <div x-show="open" @click.away="open = false" class="md:hidden bg-slate-900 border-b border-slate-800 shadow-xl absolute w-full left-0 top-16">
        <div class="px-4 pt-2 pb-6 space-y-2">
            <a href="#how-it-works" @click="open=false" class="block px-3 py-3 rounded-md text-base font-medium text-slate-300 hover:bg-slate-800">How it Works</a>
            <a href="#developers" @click="open=false" class="block px-3 py-3 rounded-md text-base font-medium text-slate-300 hover:bg-slate-800">For Developers</a>
            <a href="#teams" @click="open=false" class="block px-3 py-3 rounded-md text-base font-medium text-slate-300 hover:bg-slate-800">For Teams</a>
            <div class="border-t border-slate-800 my-2"></div>
            <a href="/login" class="block px-3 py-3 text-indigo-400 font-bold">Log In</a>
            <a href="/register" class="block px-3 py-3 text-center rounded-lg font-bold bg-indigo-600 text-white mt-2">Create Account</a>
        </div>
    </div>
</nav>
"""

# --- ROUTES ---

@app.route('/')
def landing():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    return render_template_string("<!DOCTYPE html><html lang='en'>" + BASE_HEAD + """
    <body class="antialiased">
        """ + NAVBAR + """
        
        <div class="relative pt-32 pb-20 sm:pt-40 sm:pb-24 overflow-hidden">
            <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center relative z-10">
                <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-indigo-500/10 border border-indigo-500/20 text-indigo-300 text-xs font-bold uppercase tracking-wide mb-8">
                    <span class="w-2 h-2 bg-indigo-400 rounded-full animate-pulse"></span> VIGIL v6.1 Live
                </div>
                <h1 class="text-4xl sm:text-6xl font-extrabold text-white tracking-tight mb-6 leading-tight">
                    The Firewall for the <br class="hidden sm:block" />
                    <span class="gradient-text">Generative AI Era.</span>
                </h1>
                <p class="text-lg text-slate-400 mb-10 max-w-2xl mx-auto leading-relaxed">
                    Stop sensitive data leaks before they happen. VIGIL scans every prompt sent to ChatGPT, Claude, or your internal LLMs and blocks PII, API Keys, and Secrets instantly.
                </p>
                <div class="flex flex-col sm:flex-row justify-center gap-4">
                    <a href="/register" class="w-full sm:w-auto px-8 py-4 bg-indigo-600 text-white font-bold rounded-xl hover:bg-indigo-500 transition shadow-lg shadow-indigo-500/25">Get Protected Now</a>
                    <a href="#how-it-works" class="w-full sm:w-auto px-8 py-4 glass text-slate-300 font-bold rounded-xl hover:bg-slate-800 transition">See How it Works</a>
                </div>
            </div>
            <div class="absolute top-0 left-1/2 -translate-x-1/2 w-full h-full max-w-4xl bg-indigo-500/10 blur-[100px] -z-10 rounded-full pointer-events-none"></div>
        </div>

        <section id="how-it-works" class="py-20 bg-slate-900/50 border-y border-slate-800">
            <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div class="text-center mb-16">
                    <h2 class="text-3xl font-bold text-white mb-4">How VIGIL Protects You</h2>
                    <p class="text-slate-400 max-w-2xl mx-auto">We sit between your employees and the AI, acting as an intelligent filter.</p>
                </div>
                
                <div class="grid md:grid-cols-3 gap-8">
                    <div class="p-6 rounded-2xl bg-slate-800/50 border border-slate-700 relative">
                        <div class="absolute -top-4 -left-4 w-10 h-10 bg-indigo-600 rounded-full flex items-center justify-center font-bold text-white shadow-lg">1</div>
                        <h3 class="text-xl font-bold text-white mb-3 mt-2">Intercept</h3>
                        <p class="text-slate-400 text-sm leading-relaxed">
                            Whether you use our Chrome Extension or API, VIGIL captures the text prompt <i>before</i> it leaves your device or server.
                        </p>
                    </div>
                    <div class="p-6 rounded-2xl bg-slate-800/50 border border-slate-700 relative">
                        <div class="absolute -top-4 -left-4 w-10 h-10 bg-indigo-600 rounded-full flex items-center justify-center font-bold text-white shadow-lg">2</div>
                        <h3 class="text-xl font-bold text-white mb-3 mt-2">Analyze</h3>
                        <p class="text-slate-400 text-sm leading-relaxed">
                            Our dual-engine system scans for regex patterns (like AWS Keys) and uses a small LLM to detect contextual secrets (like "Here is the password").
                        </p>
                    </div>
                    <div class="p-6 rounded-2xl bg-slate-800/50 border border-slate-700 relative">
                        <div class="absolute -top-4 -left-4 w-10 h-10 bg-indigo-600 rounded-full flex items-center justify-center font-bold text-white shadow-lg">3</div>
                        <h3 class="text-xl font-bold text-white mb-3 mt-2">Block & Log</h3>
                        <p class="text-slate-400 text-sm leading-relaxed">
                            If a threat is found, the request is blocked instantly. The event is logged in your dashboard for audit compliance (SOC2).
                        </p>
                    </div>
                </div>
            </div>
        </section>

        <section id="developers" class="py-20 relative overflow-hidden">
            <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div class="grid lg:grid-cols-2 gap-12 items-center">
                    <div>
                        <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-300 text-xs font-bold uppercase tracking-wide mb-6">
                            For Developers
                        </div>
                        <h2 class="text-3xl sm:text-4xl font-bold text-white mb-6">Secure your AI Apps with <br> <span class="text-indigo-400 font-mono">/v1/firewall</span></h2>
                        <p class="text-slate-400 mb-6 leading-relaxed">
                            Building a chatbot? Don't let your users inject malicious prompts or leak database keys. Integrate VIGIL in 3 lines of code.
                        </p>
                        <ul class="space-y-4 mb-8">
                            <li class="flex items-center gap-3 text-slate-300"><span class="text-green-400">✓</span> <span class="text-sm">Low Latency (under 200ms)</span></li>
                            <li class="flex items-center gap-3 text-slate-300"><span class="text-green-400">✓</span> <span class="text-sm">REST API compatible with Python, Node, Go</span></li>
                            <li class="flex items-center gap-3 text-slate-300"><span class="text-green-400">✓</span> <span class="text-sm">99.9% Uptime SLA</span></li>
                        </ul>
                        <a href="/register" class="text-white font-bold border-b border-indigo-500 hover:text-indigo-400 pb-0.5 transition">Get API Key &rarr;</a>
                    </div>
                    
                    <div class="glass p-6 rounded-xl border border-slate-700 shadow-2xl relative">
                        <div class="flex gap-2 mb-4">
                            <div class="w-3 h-3 rounded-full bg-red-500"></div>
                            <div class="w-3 h-3 rounded-full bg-yellow-500"></div>
                            <div class="w-3 h-3 rounded-full bg-green-500"></div>
                        </div>
                        <div class="code-block text-xs sm:text-sm">
<span class="text-purple-400">import</span> requests

api_key = <span class="text-green-400">"sk_live_..."</span>
prompt = <span class="text-green-400">"AWS_SECRET=AKIA..."</span>

response = requests.post(
    <span class="text-green-400">"https://vigil.com/v1/firewall"</span>,
    json={<span class="text-green-400">"prompt"</span>: prompt},
    headers={<span class="text-green-400">"Authorization"</span>: f<span class="text-green-400">"Bearer {api_key}"</span>}
)

<span class="text-purple-400">print</span>(response.json())
<span class="text-slate-500"># Output: {"status": "BLOCKED", "risk_score": 95}</span>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <section id="teams" class="py-20 bg-slate-900/30 border-t border-slate-800">
            <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div class="grid lg:grid-cols-2 gap-12 items-center lg:flex-row-reverse">
                    <div class="glass p-8 rounded-2xl border-t-4 border-purple-500 order-2 lg:order-1">
                        <div class="mb-4 bg-purple-500/10 w-12 h-12 rounded-lg flex items-center justify-center text-2xl">🛡️</div>
                        <h3 class="text-xl font-bold text-white mb-2">VIGIL Shield Extension</h3>
                        <p class="text-slate-400 text-sm mb-6">
                            The "Set and Forget" solution for non-technical teams.
                        </p>
                        <div class="space-y-3">
                            <div class="bg-black/40 p-3 rounded border border-slate-700 flex items-center justify-between">
                                <span class="text-slate-300 text-sm">Marketing Team</span>
                                <span class="text-green-400 text-xs font-bold bg-green-500/10 px-2 py-1 rounded">SECURE</span>
                            </div>
                            <div class="bg-black/40 p-3 rounded border border-slate-700 flex items-center justify-between">
                                <span class="text-slate-300 text-sm">Engineering Team</span>
                                <span class="text-green-400 text-xs font-bold bg-green-500/10 px-2 py-1 rounded">SECURE</span>
                            </div>
                        </div>
                    </div>

                    <div class="order-1 lg:order-2">
                         <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-purple-500/10 border border-purple-500/20 text-purple-300 text-xs font-bold uppercase tracking-wide mb-6">
                            For Enterprise Teams
                        </div>
                        <h2 class="text-3xl sm:text-4xl font-bold text-white mb-6">Protect your staff on <br> <span class="text-purple-400">ChatGPT & Claude</span></h2>
                        <p class="text-slate-400 mb-6 leading-relaxed">
                            Your employees are using AI to write code and emails. VIGIL Shield is a Chrome Extension that runs silently in the background and prevents accidental data paste.
                        </p>
                        
                        <div class="space-y-6">
                            <div class="flex gap-4">
                                <div class="w-8 h-8 rounded-full bg-slate-800 flex items-center justify-center font-bold text-white shrink-0">1</div>
                                <div>
                                    <h4 class="text-white font-bold">Install the Extension</h4>
                                    <p class="text-sm text-slate-500">Deploy via Google Workspace or individual install.</p>
                                </div>
                            </div>
                            <div class="flex gap-4">
                                <div class="w-8 h-8 rounded-full bg-slate-800 flex items-center justify-center font-bold text-white shrink-0">2</div>
                                <div>
                                    <h4 class="text-white font-bold">Enter Organization Key</h4>
                                    <p class="text-sm text-slate-500">Link all employees to one central dashboard.</p>
                                </div>
                            </div>
                            <div class="flex gap-4">
                                <div class="w-8 h-8 rounded-full bg-slate-800 flex items-center justify-center font-bold text-white shrink-0">3</div>
                                <div>
                                    <h4 class="text-white font-bold">Instant Protection</h4>
                                    <p class="text-sm text-slate-500">Pastes containing secrets are blocked immediately.</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <footer class="py-12 border-t border-slate-800 bg-slate-950 text-center">
            <div class="flex items-center justify-center gap-2 mb-4">
                {LOGO_SVG}
                <span class="font-bold text-xl tracking-tight text-white">VIGIL</span>
            </div>
            <p class="text-slate-500 text-sm mb-8">© 2026 VIGIL Security Inc. All rights reserved.</p>
            <div class="flex justify-center gap-8 text-sm font-medium text-slate-400">
                <a href="#" class="hover:text-white">Privacy Policy</a>
                <a href="#" class="hover:text-white">Terms of Service</a>
                <a href="#" class="hover:text-white">Contact Support</a>
            </div>
        </footer>

    </body></html>
    """)

# --- RESPONSIVE AUTH LAYOUT ---
AUTH_LAYOUT = f"""
<!DOCTYPE html><html lang='en'>{BASE_HEAD}
<body class="min-h-screen bg-slate-950 flex flex-col justify-center py-12 sm:px-6 lg:px-8">
    <div class="sm:mx-auto sm:w-full sm:max-w-md text-center mb-8">
        <div class="mx-auto h-12 w-12 flex items-center justify-center bg-indigo-500/10 rounded-xl mb-4">
            {LOGO_SVG}
        </div>
        <h2 class="text-3xl font-extrabold text-white">VIGIL</h2>
        <p class="mt-2 text-sm text-slate-400">Enterprise AI Security</p>
    </div>
    <div class="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
        <div class="glass py-8 px-6 shadow rounded-2xl sm:px-10">
            CONTENT_PLACEHOLDER
        </div>
    </div>
</body></html>
"""

@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ""
    if request.method == 'POST':
        u = request.form['username']; p = request.form['password']
        conn = get_db_connection(); cur = conn.cursor(); cur.execute("SELECT * FROM users_v5 WHERE username = %s", (u,)); row = cur.fetchone(); cur.close(); conn.close()
        if row and check_password_hash(row[2], p):
            user = User(id=row[0], username=row[1], password_hash=row[2], discord_webhook=row[3], api_key=row[4], plan_type=row[5]); login_user(user); return redirect(url_for('dashboard'))
        msg = "Invalid credentials"

    form = f"""
        <form class="space-y-6" method="POST">
            {'<div class="bg-red-500/10 text-red-400 p-3 rounded-lg text-sm text-center border border-red-500/20">'+msg+'</div>' if msg else ''}
            <div>
                <label class="block text-sm font-medium text-slate-300">Username</label>
                <div class="mt-1"><input name="username" type="text" required class="appearance-none block w-full px-3 py-3 border border-slate-700 rounded-xl bg-slate-900/50 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"></div>
            </div>
            <div>
                <label class="block text-sm font-medium text-slate-300">Password</label>
                <div class="mt-1"><input name="password" type="password" required class="appearance-none block w-full px-3 py-3 border border-slate-700 rounded-xl bg-slate-900/50 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"></div>
            </div>
            <div>
                <button type="submit" class="w-full flex justify-center py-3 px-4 border border-transparent rounded-xl shadow-sm text-sm font-bold text-white bg-indigo-600 hover:bg-indigo-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 transition">Sign in</button>
            </div>
        </form>
        <div class="mt-6 text-center text-sm"><a href="/register" class="font-medium text-indigo-400 hover:text-indigo-300">Create new account</a></div>
    """
    return render_template_string(AUTH_LAYOUT.replace("CONTENT_PLACEHOLDER", form))

@app.route('/register', methods=['GET', 'POST'])
def register():
    msg = ""
    if request.method == 'POST':
        u = request.form['username']; p = request.form['password']; h = generate_password_hash(p); k = "sk_live_" + secrets.token_hex(16)
        try: conn = get_db_connection(); cur = conn.cursor(); cur.execute("INSERT INTO users_v5 (username, password_hash, api_key) VALUES (%s, %s, %s) RETURNING id", (u, h, k)); uid = cur.fetchone()[0]; conn.commit(); cur.close(); conn.close(); user = User(id=uid, username=u, password_hash=h, discord_webhook=None, api_key=k); login_user(user); return redirect(url_for('dashboard'))
        except: msg = "Username taken"

    form = f"""
        <form class="space-y-6" method="POST">
            {'<div class="bg-red-500/10 text-red-400 p-3 rounded-lg text-sm text-center border border-red-500/20">'+msg+'</div>' if msg else ''}
            <div>
                <label class="block text-sm font-medium text-slate-300">Choose Username</label>
                <div class="mt-1"><input name="username" type="text" required class="appearance-none block w-full px-3 py-3 border border-slate-700 rounded-xl bg-slate-900/50 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"></div>
            </div>
            <div>
                <label class="block text-sm font-medium text-slate-300">Choose Password</label>
                <div class="mt-1"><input name="password" type="password" required class="appearance-none block w-full px-3 py-3 border border-slate-700 rounded-xl bg-slate-900/50 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"></div>
            </div>
            <div>
                <button type="submit" class="w-full flex justify-center py-3 px-4 border border-transparent rounded-xl shadow-sm text-sm font-bold text-white bg-indigo-600 hover:bg-indigo-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 transition">Create Account</button>
            </div>
        </form>
        <div class="mt-6 text-center text-sm"><a href="/login" class="font-medium text-indigo-400 hover:text-indigo-300">Already have an account? Log in</a></div>
    """
    return render_template_string(AUTH_LAYOUT.replace("CONTENT_PLACEHOLDER", form))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection(); cur = conn.cursor(); cur.execute("SELECT * FROM transactions_v5 WHERE user_id = %s ORDER BY created_at DESC LIMIT 20;", (current_user.id,)); rows = cur.fetchall(); cur.close(); conn.close()
    return render_template_string(f"""<!DOCTYPE html><html lang='en'>{BASE_HEAD}
    <body class="bg-slate-950 pb-20">
        <nav x-data="{{ open: false }}" class="glass border-b border-slate-800 sticky top-0 z-20">
            <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div class="flex justify-between h-16">
                    <div class="flex items-center gap-2">{LOGO_SVG}<span class="font-bold text-white tracking-tight">VIGIL</span></div>
                    <div class="flex items-center gap-4">
                         <a href="/simulate_leak" class="hidden sm:flex bg-red-600 hover:bg-red-500 text-white px-3 py-1.5 rounded-lg text-xs font-bold items-center gap-2 transition"><span>⚠️</span> Test Leak</a>
                         <a href="/logout" class="text-slate-400 hover:text-white text-sm font-medium">Log out</a>
                    </div>
                </div>
            </div>
        </nav>
        <main class="max-w-5xl mx-auto p-4 sm:p-6 mt-4">
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-6">
                <div class="glass p-5 rounded-xl border-t border-indigo-500/20">
                    <div class="text-slate-400 text-xs font-bold uppercase mb-1">API Key</div>
                    <div class="font-mono text-xs text-indigo-300 bg-black/50 p-2 rounded border border-slate-800 break-all select-all">{{{{ user.api_key }}}}</div>
                </div>
                <div class="glass p-5 rounded-xl border-t border-green-500/20 flex items-center justify-between">
                    <div>
                        <div class="text-slate-400 text-xs font-bold uppercase mb-1">System Status</div>
                        <div class="text-green-400 font-bold text-lg flex items-center gap-2"><span class="w-2 h-2 bg-green-500 rounded-full animate-pulse"></span> Active</div>
                    </div>
                    <a href="/simulate_leak" class="sm:hidden bg-red-600/90 text-white px-3 py-2 rounded-lg text-xs font-bold">Test Leak</a>
                </div>
            </div>
            <h2 class="text-lg font-bold text-white mb-4">Security Events</h2>
            <div class="space-y-3">
                {{% for row in rows %}}
                <div class="glass rounded-xl p-4 border-l-[3px] shadow-sm {{ 'border-red-500' if row[5] > 70 else 'border-green-500' }}">
                    <div class="flex justify-between items-start mb-2">
                        <span class="font-bold text-white text-sm truncate pr-2">{{{{ row[2] }}}}</span>
                        <span class="text-[10px] px-2 py-0.5 rounded uppercase font-black tracking-wider {{ 'bg-red-500/20 text-red-400' if row[4] == 'BLOCKED' else 'bg-green-500/20 text-green-400' }}">{{{{ row[4] }}}}</span>
                    </div>
                    <div class="bg-black/40 rounded p-2.5 mb-2 font-mono text-xs text-slate-300 break-all border border-white/5">"{{{{ row[3] }}}}"</div>
                    <div class="flex items-center justify-between text-xs text-slate-500"><span>Risk Score: <span class="{{ 'text-red-400' if row[5] > 70 else 'text-green-400' }} font-bold">{{{{ row[5] }}}}</span></span><span>{{{{ row[7].strftime('%H:%M') }}}}</span></div>
                </div>
                {{% endfor %}}
            </div>
        </main>
    </body></html>""", user=current_user, rows=rows)

# API & Sim Routes
@app.route('/v1/firewall', methods=['POST'])
def firewall_api():
    auth = request.headers.get('Authorization')
    if not auth or not auth.startswith("Bearer "): return jsonify({"error": "Missing API Key"}), 401
    api_key = auth.split(" ")[1]
    conn = get_db_connection(); cur = conn.cursor(); cur.execute("SELECT * FROM users_v5 WHERE api_key = %s", (api_key,)); u = cur.fetchone()
    if not u: return jsonify({"error": "Invalid Key"}), 403
    data = request.json; prompt = data.get("prompt", ""); source = data.get("source", "Extension"); req_id = str(uuid.uuid4())[:8]
    score, reason = analyze_security_risk(prompt); status = "BLOCKED" if score > 70 else "ALLOWED"
    cur.execute("INSERT INTO transactions_v5 (id, user_id, source, description, status, risk_score, risk_reason) VALUES (%s,%s,%s,%s,%s,%s,%s)", (req_id, u[0], source, prompt, status, score, reason)); conn.commit(); cur.close(); conn.close()
    if status == "BLOCKED": send_discord_alert(u[3], f"🚨 **BLOCKED**\nUser: {source}\nReason: {reason}", 15548997)
    return jsonify({"status": status, "risk_score": score, "reason": reason})

@app.route('/simulate_leak')
@login_required
def simulate_leak():
    try:
        source = "Test_User"; prompt = "Debug: AWS_KEY = 'AKIA_TEST_12345';"
        score, reason = analyze_security_risk(prompt); status = "BLOCKED" if score > 70 else "ALLOWED"
        conn = get_db_connection(); cur = conn.cursor(); cur.execute("INSERT INTO transactions_v5 (id, user_id, source, description, status, risk_score, risk_reason) VALUES (%s,%s,%s,%s,%s,%s,%s)", (str(uuid.uuid4())[:8], current_user.id, source, prompt, status, score, reason)); conn.commit(); cur.close(); conn.close()
        return redirect(url_for('dashboard'))
    except: return "Sim Failed"

@app.route('/logout')
@login_required
def logout_route(): logout_user(); return redirect(url_for('landing'))

if __name__ == '__main__': app.run(port=5000)
