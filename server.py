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
    try:
        client = OpenAI(api_key=OPENAI_KEY)
    except:
        print("⚠️ OpenAI Key invalid format")


# --- 🧠 VIGIL BRAIN: DATA LEAK DETECTION ---
def analyze_security_risk(prompt_text):
    if not client: return 0, "AI Not Configured"
    try:
        system_prompt = "You are VIGIL, a Data Loss Prevention (DLP) engine. Analyze input for API Keys, Passwords, PII. Return JSON: {\"risk_score\": 0-100, \"risk_reason\": \"explanation\"}."
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
        conn.commit();
        cur.close();
        conn.close()
    except Exception as e:
        print(f"❌ DB Init Error: {e}")


if DB_URL: init_db()

# --- AUTH SETUP ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'landing'


class User(UserMixin):
    def __init__(self, id, username, password_hash, discord_webhook, api_key):
        self.id = id;
        self.username = username;
        self.password_hash = password_hash;
        self.discord_webhook = discord_webhook;
        self.api_key = api_key


@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection();
    cur = conn.cursor()
    cur.execute("SELECT * FROM users_v5 WHERE id = %s", (user_id,))
    res = cur.fetchone();
    cur.close();
    conn.close()
    if res: return User(id=res[0], username=res[1], password_hash=res[2], discord_webhook=res[3], api_key=res[4])
    return None


def send_discord_alert(webhook_url, message, color=None):
    if not webhook_url: return
    try:
        requests.post(webhook_url, json={"embeds": [{"description": message, "color": color}]}, timeout=5)
    except:
        pass


# ===========================
# === PROFESSIONAL DESIGN ===
# ===========================

# We use standard strings here (no f-strings) to avoid syntax errors with HTML
BASE_HEAD = """
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VIGIL | The AI Firewall</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Inter', sans-serif; background-color: #0f172a; color: #e2e8f0; }
        .mesh-bg { background-image: radial-gradient(at 40% 20%, hsla(228,100%,74%,0.1) 0px, transparent 50%),
                                     radial-gradient(at 80% 0%, hsla(189,100%,56%,0.1) 0px, transparent 50%),
                                     radial-gradient(at 0% 50%, hsla(355,100%,93%,0.1) 0px, transparent 50%); }
        .glass-card { background: rgba(30, 41, 59, 0.7); backdrop-filter: blur(10px); border: 1px solid rgba(255, 255, 255, 0.1); }
    </style>
</head>
"""


# --- ROUTES ---

@app.route('/')
def landing():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    # Using simple concatenation + to avoid f-string crashes
    return render_template_string("<!DOCTYPE html><html lang='en' class='scroll-smooth'>" + BASE_HEAD + """
    <body class="antialiased mesh-bg">
        <nav class="max-w-7xl mx-auto px-6 py-6 flex justify-between items-center relative z-10">
            <div class="flex items-center gap-2">
                <div class="bg-indigo-600 p-2 rounded-lg"><span class="text-white font-bold">V</span></div>
                <span class="text-2xl font-extrabold tracking-tight text-white">VIGIL</span>
            </div>
            <div class="flex items-center gap-6 font-medium">
                <a href="/login" class="hover:text-indigo-400 transition">Sign In</a>
                <a href="/register" class="bg-indigo-600 hover:bg-indigo-700 text-white px-6 py-3 rounded-xl font-bold transition shadow-lg shadow-indigo-600/20">Get Started</a>
            </div>
        </nav>

        <header class="max-w-7xl mx-auto px-6 pt-20 pb-32 text-center relative z-10">
            <h1 class="text-5xl md:text-7xl font-extrabold tracking-tight mb-8 text-white leading-tight">
                The Security Layer for the <br> <span class="text-transparent bg-clip-text bg-gradient-to-r from-indigo-400 to-cyan-400">Generative AI Era.</span>
            </h1>
            <p class="text-xl text-slate-400 max-w-3xl mx-auto mb-12 leading-relaxed">
                Stop employees from accidentally pasting API keys, customer PII, and trade secrets into public AI models. VIGIL intercepts and blocks data leaks in real-time.
            </p>
            <div class="flex flex-col sm:flex-row justify-center gap-4">
                <a href="/register" class="bg-white text-slate-900 hover:bg-slate-100 text-lg px-10 py-4 rounded-xl font-bold transition shadow-xl">Start Protecting</a>
                <a href="/login" class="glass-card hover:bg-slate-800/50 text-white text-lg px-10 py-4 rounded-xl font-bold transition">Login</a>
            </div>
        </header>

        <section class="py-20 bg-slate-900/50 relative z-10 border-t border-slate-800/50">
            <div class="max-w-7xl mx-auto px-6 grid md:grid-cols-3 gap-8">
                <div class="glass-card p-8 rounded-2xl">
                    <div class="text-3xl mb-4">🛡️</div>
                    <h3 class="text-xl font-bold mb-4 text-white">1. Intercept</h3>
                    <p class="text-slate-400">We act as a secure proxy between your team and AI tools.</p>
                </div>
                <div class="glass-card p-8 rounded-2xl">
                    <div class="text-3xl mb-4">🧠</div>
                    <h3 class="text-xl font-bold mb-4 text-white">2. Analyze</h3>
                    <p class="text-slate-400">Our AI scans for keys, PII, and secrets in milliseconds.</p>
                </div>
                <div class="glass-card p-8 rounded-2xl">
                    <div class="text-3xl mb-4">🚫</div>
                    <h3 class="text-xl font-bold mb-4 text-white">3. Block</h3>
                    <p class="text-slate-400">High-risk prompts are blocked instantly before they leak.</p>
                </div>
            </div>
        </section>
    </body></html>
    """)


@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection();
    cur = conn.cursor()
    cur.execute("SELECT * FROM transactions_v5 WHERE user_id = %s ORDER BY created_at DESC;", (current_user.id,))
    rows = cur.fetchall();
    cur.close();
    conn.close()

    return render_template_string("<!DOCTYPE html><html lang='en'>" + BASE_HEAD + """
    <body class="bg-slate-900">
        <nav class="glass-card border-x-0 border-t-0 px-6 py-4 flex justify-between items-center sticky top-0 z-20">
            <div class="flex items-center gap-3"><span class="text-xl font-extrabold tracking-tight text-white">VIGIL</span></div>
            <div class="flex gap-4 text-sm font-medium">
                <a href="/settings" class="text-slate-400 hover:text-white transition">Settings</a>
                <a href="/simulate_leak" class="bg-red-600/80 hover:bg-red-500 text-white px-4 py-2 rounded-lg transition animate-pulse font-bold">⚠️ Test Leak</a>
                <a href="/logout" class="text-slate-400 hover:text-white transition">Log Out</a>
            </div>
        </nav>
        <main class="max-w-5xl mx-auto p-6 mt-8">
            <header class="mb-8"><h2 class="text-3xl font-bold text-white mb-2">Security Console</h2><p class="text-slate-400">Monitoring real-time traffic for {{ user.username }}.</p></header>

            {% if not rows %}
            <div class="text-center py-20 glass-card rounded-3xl border-dashed">
                <div class="text-5xl mb-6">🛡️</div><h3 class="text-2xl font-bold text-white mb-3">System Secure</h3>
                <p class="text-slate-400 mb-8">No incidents logged yet.</p>
                <a href="/simulate_leak" class="bg-indigo-600 hover:bg-indigo-500 text-white px-8 py-3 rounded-xl font-bold transition">Simulate Attack</a>
            </div>
            {% endif %}

            <div class="space-y-4">
                {% for row in rows %}
                <div class="glass-card rounded-xl p-6 border-l-[6px] shadow-xl transition hover:bg-slate-800/80 {{ 'border-red-500' if row[5] > 70 else 'border-green-500' }}">
                    <div class="flex justify-between items-start mb-4">
                        <div class="flex items-center gap-3">
                            <span class="font-bold text-lg text-white">{{ row[2] }}</span>
                            <span class="text-xs px-3 py-1 rounded-full uppercase font-black tracking-wider {{ 'bg-red-500 text-white' if row[4] == 'BLOCKED' else 'bg-green-500 text-white' }}">{{ row[4] }}</span>
                        </div>
                        <div class="text-slate-500 text-xs font-mono">{{ row[7] }}</div>
                    </div>
                    <div class="bg-slate-950/50 rounded-lg p-4 mb-4 font-mono text-sm text-slate-300 break-words border border-slate-800/50">"{{ row[3] }}"</div>
                    <div class="flex items-center gap-2 text-sm">
                        <span class="text-slate-500 font-semibold">AI Verdict:</span>
                        <span class="font-bold {{ 'text-red-400' if row[5] > 70 else 'text-green-400' }}">{{ row[6] }} (Risk: {{ row[5] }})</span>
                    </div>
                </div>
                {% endfor %}
            </div>
        </main>
    </body></html>
    """, user=current_user, rows=rows)


@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ""
    if request.method == 'POST':
        u = request.form['username'];
        p = request.form['password']
        conn = get_db_connection();
        cur = conn.cursor();
        cur.execute("SELECT * FROM users_v5 WHERE username = %s", (u,));
        row = cur.fetchone();
        cur.close();
        conn.close()
        if row and check_password_hash(row[2], p): user = User(id=row[0], username=row[1], password_hash=row[2],
                                                               discord_webhook=row[3], api_key=row[4]); login_user(
            user); return redirect(url_for('dashboard'))
        msg = "Invalid credentials"

    return render_template_string("<!DOCTYPE html><html lang='en'>" + BASE_HEAD + """
    <body class="bg-slate-900 flex items-center justify-center min-h-screen mesh-bg">
        <div class="glass-card p-10 rounded-3xl w-full max-w-md">
            <div class="text-center mb-8"><h2 class="text-3xl font-extrabold text-white mb-2">Sign In</h2></div>
            {% if msg %}<div class="bg-red-500/20 text-red-300 p-3 rounded-lg mb-6 text-center text-sm font-bold border border-red-500/50">{{ msg }}</div>{% endif %}
            <form method="POST" class="space-y-5">
                <input type="text" name="username" placeholder="Username" required class="w-full bg-slate-950/50 border border-slate-700 rounded-xl p-4 text-white focus:outline-none focus:border-indigo-500 transition placeholder:text-slate-600">
                <input type="password" name="password" placeholder="Password" required class="w-full bg-slate-950/50 border border-slate-700 rounded-xl p-4 text-white focus:outline-none focus:border-indigo-500 transition placeholder:text-slate-600">
                <button class="w-full bg-indigo-600 hover:bg-indigo-700 text-white font-bold py-4 rounded-xl transition shadow-lg shadow-indigo-600/20">Sign In →</button>
            </form>
            <p class="text-center mt-8 text-slate-500">New here? <a href="/register" class="text-indigo-400 font-bold hover:text-indigo-300 transition">Create an account</a></p>
        </div>
    </body></html>""", msg=msg)


@app.route('/register', methods=['GET', 'POST'])
def register():
    msg = ""
    if request.method == 'POST':
        u = request.form['username'];
        p = request.form['password'];
        h = generate_password_hash(p);
        k = "sk_live_" + secrets.token_hex(16)
        try:
            conn = get_db_connection(); cur = conn.cursor(); cur.execute(
                "INSERT INTO users_v5 (username, password_hash, api_key) VALUES (%s, %s, %s) RETURNING id",
                (u, h, k)); uid = cur.fetchone()[0]; conn.commit(); cur.close(); conn.close(); user = User(id=uid,
                                                                                                           username=u,
                                                                                                           password_hash=h,
                                                                                                           discord_webhook=None,
                                                                                                           api_key=k); login_user(
                user); return redirect(url_for('settings'))
        except:
            msg = "Username taken"

    return render_template_string("<!DOCTYPE html><html lang='en'>" + BASE_HEAD + """
    <body class="bg-slate-900 flex items-center justify-center min-h-screen mesh-bg">
        <div class="glass-card p-10 rounded-3xl w-full max-w-md">
            <div class="text-center mb-8"><h2 class="text-3xl font-extrabold text-white mb-2">Create Account</h2></div>
            {% if msg %}<div class="bg-red-500/20 text-red-300 p-3 rounded-lg mb-6 text-center text-sm font-bold border border-red-500/50">{{ msg }}</div>{% endif %}
            <form method="POST" class="space-y-5">
                <input type="text" name="username" placeholder="Username" required class="w-full bg-slate-950/50 border border-slate-700 rounded-xl p-4 text-white focus:outline-none focus:border-indigo-500 transition placeholder:text-slate-600">
                <input type="password" name="password" placeholder="Password" required class="w-full bg-slate-950/50 border border-slate-700 rounded-xl p-4 text-white focus:outline-none focus:border-indigo-500 transition placeholder:text-slate-600">
                <button class="w-full bg-indigo-600 hover:bg-indigo-700 text-white font-bold py-4 rounded-xl transition shadow-lg shadow-indigo-600/20">Create Account →</button>
            </form>
            <p class="text-center mt-8 text-slate-500">Already a member? <a href="/login" class="text-indigo-400 font-bold hover:text-indigo-300 transition">Log in</a></p>
        </div>
    </body></html>""", msg=msg)


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        wh = request.form['webhook'];
        conn = get_db_connection();
        cur = conn.cursor();
        cur.execute("UPDATE users_v5 SET discord_webhook = %s WHERE id = %s", (wh, current_user.id));
        conn.commit();
        cur.close();
        conn.close();
        current_user.discord_webhook = wh;
        return redirect(url_for('dashboard'))

    return render_template_string("<!DOCTYPE html><html lang='en'>" + BASE_HEAD + """
    <body class="bg-slate-900 flex items-center justify-center min-h-screen mesh-bg">
        <div class="glass-card p-10 rounded-3xl w-full max-w-2xl">
            <h2 class="text-3xl font-extrabold text-white mb-8">⚙️ Configuration</h2>
            <div class="mb-10">
                <label class="block text-sm font-bold text-indigo-400 mb-3 tracking-wider uppercase">Your API Key</label>
                <div class="bg-slate-950/80 p-5 rounded-xl font-mono text-green-400 break-all border border-slate-800 select-all text-sm shadow-inner">{{ user.api_key }}</div>
            </div>
            <form method="POST">
                <label class="block text-sm font-bold text-indigo-400 mb-3 tracking-wider uppercase">Discord Webhook</label>
                <input type="text" name="webhook" value="{{ user.discord_webhook or '' }}" placeholder="https://discord.com/api/webhooks/..." class="w-full bg-slate-950/50 border border-slate-700 rounded-xl p-4 text-white mb-6 focus:border-indigo-500 outline-none transition placeholder:text-slate-600">
                <button class="bg-indigo-600 hover:bg-indigo-700 text-white px-8 py-4 rounded-xl font-bold w-full transition shadow-lg shadow-indigo-600/20">Save Configuration</button>
            </form>
            <div class="mt-8 text-center"><a href="/dashboard" class="text-slate-500 hover:text-white font-medium transition">← Back to Dashboard</a></div>
        </div>
    </body></html>""", user=current_user)


@app.route('/simulate_leak')
@login_required
def simulate_leak():
    # INTERNAL LOGIC to prevent freezing
    source = "Intern_David"
    prompt = "Can you debug this connection string? postgres://admin:P@ssword123@db.production.com:5432/clients"
    req_id = str(uuid.uuid4())[:8]

    score, reason = analyze_security_risk(prompt)
    status = "BLOCKED" if score > 70 else "ALLOWED"

    conn = get_db_connection();
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO transactions_v5 (id, user_id, source, description, status, risk_score, risk_reason) VALUES (%s,%s,%s,%s,%s,%s,%s)",
        (req_id, current_user.id, source, prompt, status, score, reason))
    conn.commit();
    cur.close();
    conn.close()

    if status == "BLOCKED":
        send_discord_alert(current_user.discord_webhook,
                           f"🚨 **VIGIL BLOCKED LEAK**\nUser: {source}\nReason: {reason}\nScore: {score}", 15548997)

    return redirect(url_for('dashboard'))


@app.route('/logout')
@login_required
def logout_route(): logout_user(); return redirect(url_for('landing'))


@app.route('/v1/firewall', methods=['POST'])
def firewall_api(): return jsonify({"status": "active"})


if __name__ == '__main__': app.run(port=5000)