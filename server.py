import os
import uuid
import json
import psycopg2
import requests
import secrets
import traceback
import razorpay
import datetime
import csv
import io
from flask import Flask, request, jsonify, render_template_string, redirect, url_for, flash, Response
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

# --- DATABASE CONNECTION ---
def get_db_connection():
    if not DB_URL: raise ValueError("DATABASE_URL is missing")
    conn = psycopg2.connect(DB_URL)
    return conn

# --- INIT DB ---
def init_db():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS users_v6 (id SERIAL PRIMARY KEY, username VARCHAR(50) UNIQUE NOT NULL, password_hash TEXT NOT NULL, discord_webhook TEXT, api_key VARCHAR(64) UNIQUE, plan_type VARCHAR(20) DEFAULT 'free');""")
        cur.execute("""CREATE TABLE IF NOT EXISTS transactions_v6 (id VARCHAR(10) PRIMARY KEY, user_id INTEGER REFERENCES users_v6(id), source VARCHAR(100), description TEXT, status VARCHAR(20), risk_score INTEGER, risk_reason TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);""")
        cur.execute("""CREATE TABLE IF NOT EXISTS watchlist_v1 (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users_v6(id), keyword VARCHAR(100) NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);""")
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e: 
        print(f"❌ DB Init Error: {e}")

if DB_URL: init_db()

# --- VIGIL BRAIN ---
def analyze_security_risk(prompt_text, user_id):
    # 1. CHECK WATCHLIST
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT keyword FROM watchlist_v1 WHERE user_id = %s", (user_id,))
        rows = cur.fetchall()
        cur.close()
        conn.close()
        banned_words = [row[0] for row in rows]
        for word in banned_words:
            if word.lower() in prompt_text.lower():
                return 100, f"Contains banned keyword: '{word}'", "This keyword is strictly prohibited by your admin."
    except Exception as e: print(f"Watchlist Error: {e}")

    # 2. CHECK AI
    if not openai_client: return 0, "AI Not Configured", "Contact Admin."
    try:
        system_prompt = """You are VIGIL, a Data Loss Prevention engine. Analyze input for API Keys, Passwords, PII. 
        Return JSON: { "risk_score": 0-100, "risk_reason": "Brief explanation", "coaching_tip": "One short actionable sentence." }."""
        response = openai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": f"Scan: {prompt_text}"}],
            response_format={ "type": "json_object" }
        )
        result = json.loads(response.choices[0].message.content)
        return result.get('risk_score', 0), result.get('risk_reason', "Safe"), result.get('coaching_tip', "No issues detected.")
    except: return 50, "AI Analysis Failed", "Please try again."

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
        conn = get_db_connection(); cur = conn.cursor(); cur.execute("SELECT * FROM users_v6 WHERE id = %s", (user_id,)); res = cur.fetchone(); cur.close(); conn.close()
        if res: return User(id=res[0], username=res[1], password_hash=res[2], discord_webhook=res[3], api_key=res[4], plan_type=res[5])
    except: pass
    return None

def send_discord_alert(webhook_url, message, color=None):
    if not webhook_url: return
    try: requests.post(webhook_url, json={"embeds": [{"description": message, "color": color}]}, timeout=5)
    except: pass

# ===========================
# === UI & ROUTES ===
# ===========================

LOGO_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="w-8 h-8 text-indigo-500"><path fill-rule="evenodd" d="M12.516 2.17a.75.75 0 00-1.032 0 11.209 11.209 0 01-7.877 3.08.75.75 0 00-.722.515A12.74 12.74 0 002.25 9.75c0 5.942 4.064 10.933 9.563 12.348a.749.749 0 00.374 0c5.499-1.415 9.563-6.406 9.563-12.348 0-1.39-.223-2.73-.635-3.985a.75.75 0 00-.722-.516l-.143.001c-2.996 0-5.717-1.17-7.734-3.08zm3.094 8.016a.75.75 0 10-1.22-.872l-3.236 4.53L9.53 12.22a.75.75 0 00-1.06 1.06l2.25 2.25a.75.75 0 001.14-.094l3.75-5.25z" clip-rule="evenodd" /></svg>"""
BASE_HEAD = """<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no"><title>VIGIL | Enterprise AI Security</title><script src="https://cdn.tailwindcss.com"></script><script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script><script src="https://cdn.jsdelivr.net/npm/chart.js"></script><link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&display=swap" rel="stylesheet"><style>body { font-family: 'Plus Jakarta Sans', sans-serif; background-color: #020617; color: #f8fafc; overflow-x: hidden; } .glass { background: rgba(30, 41, 59, 0.7); backdrop-filter: blur(12px); border: 1px solid rgba(255, 255, 255, 0.08); } .hero-glow { background: radial-gradient(circle at 50% 0%, rgba(99, 102, 241, 0.15) 0%, transparent 60%); } .gradient-text { background: linear-gradient(135deg, #fff 0%, #94a3b8 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }</style></head>"""
NAVBAR_LOGGED_IN = f"""<nav x-data="{{ open: false }}" class="fixed w-full z-50 glass border-b border-slate-800 transition-all duration-300"><div class="max-w-7xl mx-auto px-6 h-20 flex justify-between items-center"><a href="/" class="flex items-center gap-3">{LOGO_SVG}<span class="text-xl font-bold tracking-tight text-white">VIGIL</span></a><div class="hidden md:flex gap-8 text-sm font-medium text-slate-400 items-center"><a href="/guide" class="text-indigo-400 font-bold hover:text-indigo-300 transition flex items-center gap-1"><span>📚</span> How to Install</a><a href="/dashboard" class="text-white hover:text-indigo-400 transition">Dashboard</a><a href="/logout" class="px-4 py-2 bg-slate-800 text-white rounded-lg font-bold hover:bg-slate-700 transition">Log Out</a></div><button @click="open = !open" class="md:hidden text-slate-300 focus:outline-none"><svg class="w-7 h-7" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"></path></svg></button></div><div x-show="open" @click.away="open = false" class="md:hidden bg-slate-900 border-b border-slate-800 absolute w-full left-0 top-20 shadow-2xl"><div class="flex flex-col p-6 gap-4 text-center"><a href="/dashboard" class="text-indigo-400 font-bold py-2">Go to Dashboard</a><a href="/logout" class="text-slate-400 py-2">Log Out</a></div></div></nav>"""
NAVBAR = NAVBAR_LOGGED_IN
FOOTER = """<footer class="py-12 text-center text-slate-600 text-sm border-t border-slate-900"><div class="flex flex-col md:flex-row justify-center items-center gap-4"><span>&copy; 2026 VIGIL Security.</span><a href="/privacy" class="text-slate-500 hover:text-indigo-400 transition">Privacy Policy</a><a href="/guide" class="text-slate-500 hover:text-indigo-400 transition">Installation</a></div></footer>"""

@app.route('/')
def landing():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    return render_template_string(f"<!DOCTYPE html><html lang='en'>{BASE_HEAD}<body class='antialiased'>{NAVBAR_LOGGED_IN.replace('Dashboard', 'Login').replace('/dashboard', '/login').replace('Log Out', 'Get Started').replace('/logout', '/register')}<div class='pt-32 pb-16 lg:pt-48 lg:pb-32 px-6 text-center hero-glow'><div class='max-w-4xl mx-auto'><div class='inline-flex items-center gap-2 px-3 py-1 rounded-full bg-indigo-950/50 border border-indigo-500/30 text-indigo-300 text-xs font-bold mb-8 uppercase tracking-wide'><span class='w-2 h-2 bg-indigo-500 rounded-full animate-pulse'></span> V12.0 Compliance Ready</div><h1 class='text-4xl sm:text-6xl lg:text-7xl font-bold tracking-tight text-white mb-6 leading-tight'>Security for the <br class='hidden sm:block' /><span class='gradient-text'>Generative AI Era.</span></h1><p class='text-lg sm:text-xl text-slate-400 mb-10 max-w-2xl mx-auto'>Stop employees from accidentally pasting API keys and PII into ChatGPT.</p><div class='flex flex-col sm:flex-row justify-center gap-4 px-4'><a href='/register' class='w-full sm:w-auto px-8 py-4 bg-indigo-600 text-white font-bold rounded-xl hover:bg-indigo-500 transition shadow-lg shadow-indigo-500/25'>Start Free</a><a href='/guide' class='w-full sm:w-auto px-8 py-4 glass text-slate-300 font-bold rounded-xl hover:bg-slate-800 transition'>How to Install</a></div></div></div>{FOOTER}</body></html>")

@app.route('/guide')
def guide():
    return render_template_string(f"<!DOCTYPE html><html lang='en'>{BASE_HEAD}<body class='bg-slate-950 pb-20'>{NAVBAR_LOGGED_IN}<main class='pt-32 max-w-4xl mx-auto px-6'><h1 class='text-3xl md:text-5xl font-bold text-white mb-6 text-center'>How to install <span class='gradient-text'>VIGIL Shield</span></h1><div class='space-y-4'><div class='glass p-6 rounded-2xl border-t border-white/5'><h3 class='font-bold text-white text-lg'>1. Download</h3><p class='text-slate-400 text-sm'>Download the .zip file of the extension.</p></div><div class='glass p-6 rounded-2xl border-t border-white/5'><h3 class='font-bold text-white text-lg'>2. Load</h3><p class='text-slate-400 text-sm'>Load unpacked in chrome://extensions.</p></div><div class='glass p-6 rounded-2xl border-t border-white/5'><h3 class='font-bold text-white text-lg'>3. Connect</h3><p class='text-slate-400 text-sm'>Enter your API Key.</p></div></div></main>{FOOTER}</body></html>")

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    msg = None; conn = get_db_connection(); cur = conn.cursor()
    if request.method == 'POST':
        if 'discord_webhook' in request.form:
            wh = request.form.get('discord_webhook', '').strip()
            cur.execute("UPDATE users_v6 SET discord_webhook = %s WHERE id = %s", (wh, current_user.id)); conn.commit(); msg = "✅ Webhook Saved"
        if 'new_keyword' in request.form:
            kw = request.form.get('new_keyword', '').strip()
            if kw: cur.execute("INSERT INTO watchlist_v1 (user_id, keyword) VALUES (%s, %s)", (current_user.id, kw)); conn.commit(); msg = f"✅ Added '{kw}'"
        if 'delete_keyword' in request.form:
            kid = request.form.get('delete_keyword')
            cur.execute("DELETE FROM watchlist_v1 WHERE id = %s AND user_id = %s", (kid, current_user.id)); conn.commit(); msg = "🗑️ Keyword Removed"

    cur.execute("SELECT * FROM transactions_v6 WHERE user_id = %s ORDER BY created_at DESC LIMIT 20;", (current_user.id,)); rows = cur.fetchall()
    cur.execute("SELECT * FROM watchlist_v1 WHERE user_id = %s ORDER BY created_at DESC;", (current_user.id,)); watchlist_rows = cur.fetchall()
    cur.execute("SELECT COUNT(*) FROM transactions_v6 WHERE user_id = %s", (current_user.id,)); total_scans = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM transactions_v6 WHERE user_id = %s AND status='BLOCKED'", (current_user.id,)); total_blocked = cur.fetchone()[0]
    protection_rate = int((total_blocked / total_scans * 100) if total_scans > 0 else 100)
    cur.execute("""SELECT DATE(created_at) as date, COUNT(*) FROM transactions_v6 WHERE user_id = %s AND created_at > current_date - interval '7 days' GROUP BY date ORDER BY date""", (current_user.id,))
    chart_rows = cur.fetchall(); chart_labels = [r[0].strftime('%b %d') for r in chart_rows]; chart_data = [r[1] for r in chart_rows]
    cur.close(); conn.close()
    
    return render_template_string(f"<!DOCTYPE html><html lang='en'>{BASE_HEAD}<body class='bg-slate-950 pb-20'>{NAVBAR_LOGGED_IN}<main class='pt-32 max-w-7xl mx-auto px-6'><div class='flex flex-col md:flex-row justify-between items-start md:items-center mb-8 gap-4'><div><h2 class='text-2xl font-bold text-white'>Security Command Center</h2><p class='text-slate-400 text-sm'>Real-time threat monitoring.</p></div><div class='flex gap-3'><a href='/export_logs' class='bg-slate-800 hover:bg-slate-700 text-white px-4 py-2 rounded-lg text-sm font-bold border border-slate-700 transition flex items-center gap-2'><span>📥</span> Export Logs</a><a href='/simulate_leak' class='bg-red-600 hover:bg-red-500 text-white px-4 py-2 rounded-lg text-sm font-bold shadow-lg shadow-red-500/20 flex items-center gap-2 transition'><span>⚠️</span> Simulate Leak</a></div></div>{% if msg %}<div class='mb-6 p-4 rounded-xl bg-indigo-500/20 border border-indigo-500/40 text-indigo-200 font-bold text-center animate-pulse'>{msg}</div>{% endif %}<div class='grid grid-cols-1 md:grid-cols-3 gap-6 mb-8'><div class='glass p-6 rounded-2xl border-t border-white/10'><div class='text-slate-400 text-xs font-bold uppercase mb-2'>Total Scans</div><div class='text-4xl font-bold text-white'>{total_scans}</div></div><div class='glass p-6 rounded-2xl border-t border-red-500/20'><div class='text-red-400 text-xs font-bold uppercase mb-2'>Threats Blocked</div><div class='text-4xl font-bold text-white'>{total_blocked}</div></div><div class='glass p-6 rounded-2xl border-t border-green-500/20'><div class='text-green-400 text-xs font-bold uppercase mb-2'>Protection Rate</div><div class='text-4xl font-bold text-white'>{protection_rate}%</div></div></div><div class='grid grid-cols-1 lg:grid-cols-3 gap-8'><div class='lg:col-span-2 space-y-8'><div class='glass p-6 rounded-2xl border-t border-blue-500/20'><h3 class='text-lg font-bold text-white mb-4 flex items-center gap-2'>🚫 Custom Watchlist</h3><form method='POST' class='flex gap-2 mb-4'><input type='text' name='new_keyword' placeholder='Add banned word...' class='w-full bg-black/50 border border-slate-800 rounded px-3 py-2 text-sm text-white'><button class='bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded text-sm font-bold'>Add</button></form><div class='flex flex-wrap gap-2'>{% for item in watchlist %}<form method='POST' class='inline'><input type='hidden' name='delete_keyword' value='{item[0]}'><button class='px-3 py-1 bg-slate-800 border border-slate-700 rounded-full text-xs text-slate-300'>{item[2]} ×</button></form>{% endfor %}</div></div><div class='glass p-6 rounded-2xl border-t border-white/10'><h3 class='text-lg font-bold text-white mb-4'>Recent Events</h3><div class='space-y-3'>{% for row in rows %}<div class='glass rounded-xl p-4 border-l-[4px] {{ 'border-red-500' if row[5] > 70 else 'border-green-500' }}'><div class='flex justify-between items-center mb-2'><span class='font-bold text-white text-sm'>{row[2]}</span><span class='text-[10px] px-2 py-0.5 rounded uppercase font-black tracking-wider {{ 'bg-red-500/20 text-red-400' if row[4] == 'BLOCKED' else 'bg-green-500/20 text-green-400' }}'>{row[4]}</span></div><div class='bg-black/30 p-2 rounded border border-white/5 font-mono text-xs text-slate-300 break-all mb-2'>"{row[3]}"</div></div>{% endfor %}</div></div></div><div class='space-y-6'><div class='glass p-6 rounded-2xl border-t border-white/10 mb-8'><h3 class='text-lg font-bold text-white mb-4'>Trend</h3><div class='h-40'><canvas id='activityChart'></canvas></div></div><div class='glass p-6 rounded-2xl border-t border-indigo-500/20'><div class='text-indigo-400 text-xs font-bold uppercase mb-2'>API Key</div><div class='font-mono text-xs text-white bg-black/50 p-3 rounded border border-slate-800 break-all select-all'>{user.api_key}</div></div></div></div></main><script>const ctx=document.getElementById('activityChart');new Chart(ctx,{{type:'line',data:{{labels:{chart_labels|tojson},datasets:[{{label:'Scans',data:{chart_data|tojson},borderColor:'#6366f1',backgroundColor:'rgba(99, 102, 241, 0.1)',tension:0.4,fill:true}}]}},options:{{responsive:true,maintainAspectRatio:false,plugins:{{legend:{{display:false}}}},scales:{{y:{{grid:{{color:'rgba(255,255,255,0.05)'}}}},x:{{grid:{{display:false}}}}}}}}}});</script></body></html>""", user=current_user, rows=rows, watchlist=watchlist_rows, current_user=current_user, msg=msg, total_scans=total_scans, total_blocked=total_blocked, protection_rate=protection_rate, chart_labels=chart_labels, chart_data=chart_data)

# --- CSV EXPORT ROUTE ---
@app.route('/export_logs')
@login_required
def export_logs():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT created_at, source, status, risk_score, risk_reason, description FROM transactions_v6 WHERE user_id = %s ORDER BY created_at DESC", (current_user.id,))
    rows = cur.fetchall()
    cur.close(); conn.close()

    # Generate CSV in memory
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['Timestamp', 'Source', 'Status', 'Risk Score', 'Reason', 'Snippet'])
    for row in rows:
        cw.writerow([row[0], row[1], row[2], row[3], row[4], row[5]])
    
    output = si.getvalue()
    return Response(output, mimetype="text/csv", headers={"Content-disposition": "attachment; filename=vigil_security_audit.csv"})

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u = request.form['username']; p = request.form['password']
        conn = get_db_connection(); cur = conn.cursor(); cur.execute("SELECT * FROM users_v6 WHERE username = %s", (u,)); row = cur.fetchone(); cur.close(); conn.close()
        if row and check_password_hash(row[2], p):
            user = User(id=row[0], username=row[1], password_hash=row[2], discord_webhook=row[3], api_key=row[4], plan_type=row[5]); login_user(user); return redirect(url_for('dashboard'))
    return render_template_string(f"<!DOCTYPE html><html lang='en'>{BASE_HEAD}<body class='min-h-screen bg-slate-950 flex flex-col justify-center py-12 sm:px-6 lg:px-8'><div class='sm:mx-auto sm:w-full sm:max-w-md text-center mb-8'><h2 class='text-3xl font-extrabold text-white'>VIGIL Login</h2></div><div class='mt-8 sm:mx-auto sm:w-full sm:max-w-md'><div class='glass py-8 px-6 shadow rounded-2xl'><form class='space-y-6' method='POST'><div><label class='block text-sm font-medium text-slate-300'>Username</label><input name='username' type='text' required class='block w-full px-3 py-3 border border-slate-700 rounded-xl bg-slate-900/50 text-white'></div><div><label class='block text-sm font-medium text-slate-300'>Password</label><input name='password' type='password' required class='block w-full px-3 py-3 border border-slate-700 rounded-xl bg-slate-900/50 text-white'></div><button type='submit' class='w-full py-3 px-4 bg-indigo-600 rounded-xl text-white font-bold'>Sign in</button></form><div class='mt-6 text-center'><a href='/register' class='text-slate-400 hover:text-white'>Create Account</a></div></div></div></body></html>")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        u = request.form['username']; p = request.form['password']; h = generate_password_hash(p); k = "sk_live_" + secrets.token_hex(16)
        try: conn = get_db_connection(); cur = conn.cursor(); cur.execute("INSERT INTO users_v6 (username, password_hash, api_key) VALUES (%s, %s, %s) RETURNING id", (u, h, k)); uid = cur.fetchone()[0]; conn.commit(); cur.close(); conn.close(); user = User(id=uid, username=u, password_hash=h, discord_webhook=None, api_key=k); login_user(user); return redirect(url_for('dashboard'))
        except: pass
    return render_template_string(f"<!DOCTYPE html><html lang='en'>{BASE_HEAD}<body class='min-h-screen bg-slate-950 flex flex-col justify-center py-12 sm:px-6 lg:px-8'><div class='sm:mx-auto sm:w-full sm:max-w-md text-center mb-8'><h2 class='text-3xl font-extrabold text-white'>Create Account</h2></div><div class='mt-8 sm:mx-auto sm:w-full sm:max-w-md'><div class='glass py-8 px-6 shadow rounded-2xl'><form class='space-y-6' method='POST'><div><label class='block text-sm font-medium text-slate-300'>Username</label><input name='username' type='text' required class='block w-full px-3 py-3 border border-slate-700 rounded-xl bg-slate-900/50 text-white'></div><div><label class='block text-sm font-medium text-slate-300'>Password</label><input name='password' type='password' required class='block w-full px-3 py-3 border border-slate-700 rounded-xl bg-slate-900/50 text-white'></div><button type='submit' class='w-full py-3 px-4 bg-indigo-600 rounded-xl text-white font-bold'>Register</button></form><div class='mt-6 text-center'><a href='/login' class='text-slate-400 hover:text-white'>Already have account?</a></div></div></div></body></html>")

@app.route('/v1/firewall', methods=['POST'])
def firewall_api():
    auth = request.headers.get('Authorization')
    if not auth or not auth.startswith("Bearer "): return jsonify({"error": "Missing API Key"}), 401
    api_key = auth.split(" ")[1]
    conn = get_db_connection(); cur = conn.cursor(); cur.execute("SELECT * FROM users_v6 WHERE api_key = %s", (api_key,)); u = cur.fetchone(); cur.close(); conn.close()
    if not u: return jsonify({"error": "Invalid Key"}), 403
    data = request.json; prompt = data.get("prompt", ""); source = data.get("source", "Extension"); req_id = str(uuid.uuid4())[:8]
    score, reason, tip = analyze_security_risk(prompt, u[0]); status = "BLOCKED" if score > 70 else "ALLOWED"
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("INSERT INTO transactions_v6 (id, user_id, source, description, status, risk_score, risk_reason) VALUES (%s,%s,%s,%s,%s,%s,%s)", (req_id, u[0], source, prompt, status, score, reason))
    conn.commit(); cur.close(); conn.close()
    if status == "BLOCKED": send_discord_alert(u[3], f"🚨 **BLOCKED**\nUser: {source}\nReason: {reason}", 15548997)
    return jsonify({"status": status, "risk_score": score, "reason": reason, "coaching_tip": tip})

@app.route('/simulate_leak')
@login_required
def simulate_leak():
    try:
        source = "Test_User"; prompt = "Debug: AWS_KEY = 'AKIA_TEST_12345';"
        score, reason, tip = analyze_security_risk(prompt, current_user.id); status = "BLOCKED" if score > 70 else "ALLOWED"
        conn = get_db_connection(); cur = conn.cursor(); cur.execute("INSERT INTO transactions_v6 (id, user_id, source, description, status, risk_score, risk_reason) VALUES (%s,%s,%s,%s,%s,%s,%s)", (str(uuid.uuid4())[:8], current_user.id, source, prompt, status, score, reason)); conn.commit(); cur.close(); conn.close()
        if status == "BLOCKED": send_discord_alert(current_user.discord_webhook, f"🚨 **BLOCKED**\nUser: {source}\nReason: {reason}", 15548997)
        return redirect(url_for('dashboard'))
    except Exception as e: return f"Sim Failed: {e}"

@app.route('/logout')
@login_required
def logout_route(): logout_user(); return redirect(url_for('landing'))

if __name__ == '__main__': app.run(port=5000)
