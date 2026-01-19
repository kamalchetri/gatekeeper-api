import os
import uuid
import json
import psycopg2
import requests
import secrets
import traceback
import razorpay
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template_string, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from openai import OpenAI
from flask_cors import CORS

app = Flask(__name__)
# SAFETY: Verify CORS is installed. If not, this might cause crash, but usually 502, not 500.
try:
    CORS(app)
except:
    print("WARNING: CORS failed to load.")

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

# REMOVED CSS VARIABLES FROM BASE_HEAD TO PREVENT F-STRING ERRORS
BASE_HEAD = """
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>VIGIL | Enterprise AI Security</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Inter', sans-serif; background-color: #0f172a; color: #f8fafc; }
        .glass { background: rgba(30, 41, 59, 0.7); backdrop-filter: blur(10px); border: 1px solid rgba(255, 255, 255, 0.08); }
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
                <a href="/login" class="text-sm font-medium text-indigo-400 hover:text-indigo-300 transition">Log In</a>
            </div>
        </div>
    </div>
</nav>
"""

# --- ROUTES ---

@app.route('/')
def landing():
    return render_template_string("<!DOCTYPE html><html lang='en'>" + BASE_HEAD + """
    <body class="antialiased">
        """ + NAVBAR + """
        <div class="pt-40 text-center px-4">
            <h1 class="text-5xl font-bold text-white mb-6">VIGIL Security</h1>
            <a href="/login" class="bg-indigo-600 text-white px-8 py-4 rounded-xl font-bold">Log In</a>
        </div>
    </body></html>
    """)

# --- DEBUG: WRAPPED LOGIN ROUTE ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    try:
        msg = ""
        if request.method == 'POST':
            u = request.form['username']; p = request.form['password']
            conn = get_db_connection(); cur = conn.cursor(); cur.execute("SELECT * FROM users_v5 WHERE username = %s", (u,)); row = cur.fetchone(); cur.close(); conn.close()
            if row and check_password_hash(row[2], p):
                user = User(id=row[0], username=row[1], password_hash=row[2], discord_webhook=row[3], api_key=row[4], plan_type=row[5])
                login_user(user)
                return redirect(url_for('dashboard'))
            msg = "Invalid credentials"

        form = f"""
            <h2 class="text-3xl font-bold text-white mb-6 text-center">Login Debug Mode</h2>
            <form class="space-y-6" method="POST">
                {'<div class="bg-red-500/10 text-red-400 p-3 rounded">'+msg+'</div>' if msg else ''}
                <input name="username" type="text" placeholder="Username" required class="w-full px-3 py-3 rounded-xl bg-slate-900 border border-slate-700 text-white">
                <input name="password" type="password" placeholder="Password" required class="w-full px-3 py-3 rounded-xl bg-slate-900 border border-slate-700 text-white">
                <button type="submit" class="w-full py-3 bg-indigo-600 text-white font-bold rounded-xl">Sign In</button>
            </form>
            <div class="mt-4 text-center"><a href="/register" class="text-indigo-400">Create Account</a></div>
        """
        
        layout = f"""<!DOCTYPE html><html lang='en'>{BASE_HEAD}<body class="bg-slate-950 flex flex-col justify-center min-h-screen px-4"><div class="max-w-md w-full mx-auto glass p-8 rounded-2xl">{form}</div></body></html>"""
        return render_template_string(layout)
    except Exception as e:
        return f"<h1>LOGIN CRASH REPORT 🚨</h1><pre>{traceback.format_exc()}</pre>"

@app.route('/register', methods=['GET', 'POST'])
def register():
    try:
        msg = ""
        if request.method == 'POST':
            u = request.form['username']; p = request.form['password']; h = generate_password_hash(p); k = "sk_live_" + secrets.token_hex(16)
            try: conn = get_db_connection(); cur = conn.cursor(); cur.execute("INSERT INTO users_v5 (username, password_hash, api_key) VALUES (%s, %s, %s) RETURNING id", (u, h, k)); uid = cur.fetchone()[0]; conn.commit(); cur.close(); conn.close(); user = User(id=uid, username=u, password_hash=h, discord_webhook=None, api_key=k); login_user(user); return redirect(url_for('dashboard'))
            except: msg = "Username taken"

        form = f"""
            <h2 class="text-3xl font-bold text-white mb-6 text-center">Register</h2>
            <form class="space-y-6" method="POST">
                {'<div class="bg-red-500/10 text-red-400 p-3 rounded">'+msg+'</div>' if msg else ''}
                <input name="username" type="text" placeholder="Username" required class="w-full px-3 py-3 rounded-xl bg-slate-900 border border-slate-700 text-white">
                <input name="password" type="password" placeholder="Password" required class="w-full px-3 py-3 rounded-xl bg-slate-900 border border-slate-700 text-white">
                <button type="submit" class="w-full py-3 bg-indigo-600 text-white font-bold rounded-xl">Create Account</button>
            </form>
        """
        layout = f"""<!DOCTYPE html><html lang='en'>{BASE_HEAD}<body class="bg-slate-950 flex flex-col justify-center min-h-screen px-4"><div class="max-w-md w-full mx-auto glass p-8 rounded-2xl">{form}</div></body></html>"""
        return render_template_string(layout)
    except Exception as e:
         return f"<h1>REGISTER CRASH REPORT 🚨</h1><pre>{traceback.format_exc()}</pre>"

# --- DEBUG: WRAPPED DASHBOARD ROUTE ---
@app.route('/dashboard')
@login_required
def dashboard():
    try:
        conn = get_db_connection(); cur = conn.cursor()
        
        # 1. Fetch Recent Logs
        cur.execute("SELECT * FROM transactions_v5 WHERE user_id = %s ORDER BY created_at DESC LIMIT 50;", (current_user.id,))
        rows = cur.fetchall()
        
        # 2. Calculate Analytics
        total_scans = len(rows)
        blocked_scans = sum(1 for r in rows if r[4] == 'BLOCKED')
        safe_scans = total_scans - blocked_scans
        
        # 3. Trend Data
        trend_labels = [r[7].strftime('%H:%M') for r in reversed(rows)]
        trend_data = [r[5] for r in reversed(rows)]
        
        cur.close(); conn.close()
        
        return render_template_string(f"""<!DOCTYPE html><html lang='en'>{BASE_HEAD}
        <body class="bg-slate-950 pb-20">
            <nav class="glass border-b border-slate-800 p-4 sticky top-0 z-20 flex justify-between">
                <div class="font-bold text-white">VIGIL DASHBOARD</div>
                <a href="/logout" class="text-slate-400">Logout</a>
            </nav>

            <main class="max-w-6xl mx-auto p-4 mt-4">
                <div class="glass p-4 rounded-xl border border-indigo-500/20 mb-8 break-all font-mono text-xs text-indigo-300">
                    API KEY: {{{{ user.api_key }}}}
                </div>

                <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
                    <div class="glass p-6 rounded-2xl h-64 relative">
                        <canvas id="pieChart"></canvas>
                    </div>
                    <div class="glass p-6 rounded-2xl h-64 relative">
                        <canvas id="lineChart"></canvas>
                    </div>
                </div>

                <h2 class="text-lg font-bold text-white mb-4">Logs</h2>
                <div class="space-y-3">
                    {{% for row in rows %}}
                    <div class="glass rounded-xl p-4 border-l-[3px] {{ 'border-red-500' if row[5] > 70 else 'border-green-500' }}">
                        <div class="flex justify-between text-sm text-white font-bold">
                            <span>{{{{ row[2] }}}}</span>
                            <span>{{{{ row[4] }}}}</span>
                        </div>
                        <div class="bg-black/40 rounded p-2 my-2 text-xs text-slate-300 font-mono">"{{{{ row[3] }}}}"</div>
                    </div>
                    {{% endfor %}}
                </div>
            </main>
            
            <script>
                // Pie Chart
                new Chart(document.getElementById('pieChart'), {{
                    type: 'doughnut',
                    data: {{
                        labels: ['Safe', 'Blocked'],
                        datasets: [{{ data: [{safe_scans}, {blocked_scans}], backgroundColor: ['#10b981', '#ef4444'] }}]
                    }},
                    options: {{ maintainAspectRatio: false }}
                }});

                // Line Chart
                new Chart(document.getElementById('lineChart'), {{
                    type: 'line',
                    data: {{
                        labels: {trend_labels},
                        datasets: [{{
                            label: 'Risk',
                            data: {trend_data},
                            borderColor: '#6366f1',
                            fill: true
                        }}]
                    }},
                    options: {{ maintainAspectRatio: false, scales: {{ x: {{ display: false }} }} }}
                }});
            </script>
        </body></html>""", user=current_user, rows=rows, safe_scans=safe_scans, blocked_scans=blocked_scans, trend_labels=trend_labels, trend_data=trend_data)
    
    except Exception as e:
        return f"<h1>DASHBOARD CRASH REPORT 🚨</h1><pre>{traceback.format_exc()}</pre>"

@app.route('/v1/firewall', methods=['POST'])
def firewall_api():
    try:
        auth = request.headers.get('Authorization')
        if not auth or not auth.startswith("Bearer "): return jsonify({"error": "Missing API Key"}), 401
        api_key = auth.split(" ")[1]
        conn = get_db_connection(); cur = conn.cursor(); cur.execute("SELECT * FROM users_v5 WHERE api_key = %s", (api_key,)); u = cur.fetchone()
        if not u: return jsonify({"error": "Invalid Key"}), 403
        data = request.json; prompt = data.get("prompt", ""); source = data.get("source", "Extension"); req_id = str(uuid.uuid4())[:8]
        score, reason = analyze_security_risk(prompt); status = "BLOCKED" if score > 70 else "ALLOWED"
        cur.execute("INSERT INTO transactions_v5 (id, user_id, source, description, status, risk_score, risk_reason) VALUES (%s,%s,%s,%s,%s,%s,%s)", (req_id, u[0], source, prompt, status, score, reason)); conn.commit(); cur.close(); conn.close()
        return jsonify({"status": status, "risk_score": score, "reason": reason})
    except: return jsonify({"error": "Internal Error"}), 500

@app.route('/logout')
@login_required
def logout_route(): logout_user(); return redirect(url_for('landing'))

if __name__ == '__main__': app.run(port=5000)
