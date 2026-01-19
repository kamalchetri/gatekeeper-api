import os
import uuid
import json
import psycopg2
import requests
import secrets
import traceback
from flask import Flask, request, jsonify, render_template_string, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from openai import OpenAI

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'vigil_secret_key_999')

# --- CONFIGURATION ---
DB_URL = os.environ.get('DATABASE_URL')
OPENAI_KEY = os.environ.get('OPENAI_API_KEY')

client = None
if OPENAI_KEY:
    try:
        client = OpenAI(api_key=OPENAI_KEY)
    except:
        print("⚠️ OpenAI Key configuration issue")


# --- 🧠 VIGIL BRAIN ---
def analyze_security_risk(prompt_text):
    if not client: return 0, "AI Not Configured (Check API Key)"
    try:
        system_prompt = "You are VIGIL, a Data Loss Prevention (DLP) engine. Analyze input for API Keys (sk-, AWS), Passwords, PII. Return JSON: {\"risk_score\": 0-100, \"risk_reason\": \"explanation\"}."
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
        return 50, "AI Analysis Failed"


# --- DATABASE SETUP (V5) ---
def get_db_connection():
    if not DB_URL: raise ValueError("DATABASE_URL is missing")
    conn = psycopg2.connect(DB_URL)
    return conn


def init_db():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        # Users Table
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
        # Transactions Table
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
login_manager.login_view = 'login'


class User(UserMixin):
    def __init__(self, id, username, password_hash, discord_webhook, api_key):
        self.id = id;
        self.username = username;
        self.password_hash = password_hash;
        self.discord_webhook = discord_webhook;
        self.api_key = api_key


@login_manager.user_loader
def load_user(user_id):
    try:
        conn = get_db_connection();
        cur = conn.cursor()
        cur.execute("SELECT * FROM users_v5 WHERE id = %s", (user_id,))
        res = cur.fetchone();
        cur.close();
        conn.close()
        if res: return User(id=res[0], username=res[1], password_hash=res[2], discord_webhook=res[3], api_key=res[4])
    except:
        pass
    return None


def send_discord_alert(webhook_url, message, color=None):
    if not webhook_url: return
    try:
        requests.post(webhook_url, json={"embeds": [{"description": message, "color": color}]}, timeout=5)
    except:
        pass


# ===========================
# === PROFESSIONAL UI ===
# ===========================

# Shared CSS & Head
BASE_HEAD = """
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VIGIL | Enterprise AI Security</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Plus Jakarta Sans', sans-serif; background-color: #020617; color: #f8fafc; }
        .logo-text { letter-spacing: -0.05em; }
        .glass { background: rgba(30, 41, 59, 0.4); backdrop-filter: blur(12px); border: 1px solid rgba(255, 255, 255, 0.05); }
        .gradient-text { background: linear-gradient(135deg, #fff 0%, #94a3b8 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .hero-glow { background: radial-gradient(circle at 50% 0%, rgba(99, 102, 241, 0.15) 0%, transparent 50%); }
    </style>
</head>
"""

NAVBAR = """
<nav class="fixed w-full z-50 glass border-b border-slate-800">
    <div class="max-w-7xl mx-auto px-6 h-20 flex justify-between items-center">
        <a href="/" class="flex items-center gap-3 group">
            <div class="w-10 h-10 bg-indigo-600 rounded-xl flex items-center justify-center text-white font-bold text-xl shadow-lg shadow-indigo-500/20 group-hover:scale-105 transition">V</div>
            <span class="text-xl font-bold logo-text text-white">VIGIL</span>
        </a>
        <div class="hidden md:flex gap-8 text-sm font-medium text-slate-400">
            <a href="/#how" class="hover:text-white transition">Platform</a>
            <a href="/#features" class="hover:text-white transition">Features</a>
        </div>
        <div class="flex gap-4">
            <a href="/login" class="px-5 py-2.5 text-sm font-medium text-slate-300 hover:text-white transition">Log in</a>
            <a href="/register" class="px-5 py-2.5 text-sm font-bold bg-white text-slate-950 rounded-lg hover:bg-indigo-50 transition shadow-xl shadow-white/5">Start Free</a>
        </div>
    </div>
</nav>
"""


# --- ROUTES ---

@app.route('/')
def landing():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    return render_template_string("<!DOCTYPE html><html lang='en'>" + BASE_HEAD + """
    <body class="antialiased selection:bg-indigo-500 selection:text-white">
        """ + NAVBAR + """

        <div class="relative pt-32 pb-20 lg:pt-48 lg:pb-32 overflow-hidden hero-glow">
            <div class="max-w-7xl mx-auto px-6 text-center relative z-10">
                <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-indigo-950/50 border border-indigo-500/30 text-indigo-300 text-xs font-semibold mb-8 uppercase tracking-wide">
                    <span class="w-2 h-2 bg-indigo-500 rounded-full animate-pulse"></span> v3.0 Live
                </div>
                <h1 class="text-5xl md:text-7xl font-bold tracking-tight mb-8 leading-[1.1]">
                    The Firewall for <br>
                    <span class="gradient-text">Artificial Intelligence.</span>
                </h1>
                <p class="text-xl text-slate-400 max-w-2xl mx-auto mb-12 leading-relaxed">
                    Prevent data leaks before they happen. VIGIL intercepts employee AI prompts, scans for secrets, and blocks PII in real-time.
                </p>
                <div class="flex flex-col sm:flex-row justify-center gap-4">
                    <a href="/register" class="px-8 py-4 text-lg font-bold bg-indigo-600 text-white rounded-xl hover:bg-indigo-500 transition shadow-lg shadow-indigo-500/25">Deploy Firewall</a>
                    <a href="/login" class="px-8 py-4 text-lg font-medium text-slate-300 glass rounded-xl hover:bg-slate-800 transition">View Demo</a>
                </div>
            </div>
        </div>

        <section id="how" class="py-24 border-t border-slate-800 bg-slate-900/50">
            <div class="max-w-7xl mx-auto px-6">
                <div class="grid md:grid-cols-3 gap-12">
                    <div class="relative group">
                        <div class="absolute -inset-1 bg-gradient-to-r from-indigo-500 to-purple-600 rounded-2xl blur opacity-25 group-hover:opacity-50 transition"></div>
                        <div class="relative h-full bg-slate-900 p-8 rounded-xl border border-slate-800">
                            <div class="w-12 h-12 bg-slate-800 rounded-lg flex items-center justify-center text-2xl mb-6">⚡</div>
                            <h3 class="text-xl font-bold text-white mb-3">1. Intercept</h3>
                            <p class="text-slate-400">Employees use VIGIL as a proxy. We catch every request before it hits OpenAI or Claude.</p>
                        </div>
                    </div>
                    <div class="relative group">
                        <div class="absolute -inset-1 bg-gradient-to-r from-blue-500 to-cyan-600 rounded-2xl blur opacity-25 group-hover:opacity-50 transition"></div>
                        <div class="relative h-full bg-slate-900 p-8 rounded-xl border border-slate-800">
                            <div class="w-12 h-12 bg-slate-800 rounded-lg flex items-center justify-center text-2xl mb-6">🧠</div>
                            <h3 class="text-xl font-bold text-white mb-3">2. Analyze</h3>
                            <p class="text-slate-400">Our DLP Engine scans for 50+ types of secrets: AWS Keys, SQL passwords, and PII.</p>
                        </div>
                    </div>
                    <div class="relative group">
                        <div class="absolute -inset-1 bg-gradient-to-r from-red-500 to-orange-600 rounded-2xl blur opacity-25 group-hover:opacity-50 transition"></div>
                        <div class="relative h-full bg-slate-900 p-8 rounded-xl border border-slate-800">
                            <div class="w-12 h-12 bg-slate-800 rounded-lg flex items-center justify-center text-2xl mb-6">🛡️</div>
                            <h3 class="text-xl font-bold text-white mb-3">3. Block</h3>
                            <p class="text-slate-400">Dangerous prompts are rejected instantly. Security teams are notified via Discord.</p>
                        </div>
                    </div>
                </div>
            </div>
        </section>
    </body></html>
    """)


# --- AUTH LAYOUT (SPLIT SCREEN) ---
AUTH_LAYOUT = """
<!DOCTYPE html><html lang='en'>""" + BASE_HEAD + """
<body class="h-screen flex overflow-hidden">
    <div class="hidden lg:flex w-1/2 bg-slate-900 relative flex-col justify-between p-12 border-r border-slate-800">
        <div class="absolute inset-0 hero-glow opacity-50"></div>
        <div class="relative z-10">
            <div class="flex items-center gap-3 mb-12">
                <div class="w-8 h-8 bg-indigo-600 rounded-lg flex items-center justify-center font-bold">V</div>
                <span class="font-bold text-xl tracking-tight">VIGIL</span>
            </div>
            <h2 class="text-4xl font-bold leading-tight mb-6">Secure your AI <br>workflow today.</h2>
            <p class="text-slate-400 text-lg max-w-md">Join 500+ engineering teams using VIGIL to prevent accidental data leaks in the Generative AI era.</p>
        </div>
        <div class="relative z-10 glass p-6 rounded-2xl border-slate-700">
            <div class="flex gap-1 text-yellow-500 mb-3">★★★★★</div>
            <p class="text-slate-300 italic mb-4">"VIGIL caught an intern pasting a live AWS production key into ChatGPT. It saved us from a massive breach."</p>
            <div class="flex items-center gap-3">
                <div class="w-10 h-10 bg-slate-700 rounded-full"></div>
                <div><div class="font-bold text-white">Alex Chen</div><div class="text-xs text-slate-500">CTO, FinTech Co</div></div>
            </div>
        </div>
    </div>

    <div class="w-full lg:w-1/2 bg-slate-950 flex flex-col justify-center px-8 lg:px-24 relative">
        <div class="max-w-md w-full mx-auto">
            CONTENT_PLACEHOLDER
        </div>
    </div>
</body></html>
"""


@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ""
    if request.method == 'POST':
        u = request.form['username'];
        p = request.form['password']
        conn = get_db_connection();
        cur = conn.cursor()
        cur.execute("SELECT * FROM users_v5 WHERE username = %s", (u,))
        row = cur.fetchone();
        cur.close();
        conn.close()
        if row and check_password_hash(row[2], p):
            user = User(id=row[0], username=row[1], password_hash=row[2], discord_webhook=row[3], api_key=row[4])
            login_user(user);
            return redirect(url_for('dashboard'))
        msg = "Invalid username or password."

    form_html = f"""
        <h2 class="text-3xl font-bold text-white mb-2">Welcome back</h2>
        <p class="text-slate-400 mb-8">Enter your credentials to access the console.</p>
        {'<div class="bg-red-500/10 text-red-400 p-3 rounded-lg mb-6 text-sm border border-red-500/20">' + msg + '</div>' if msg else ''}
        <form method="POST" class="space-y-5">
            <div>
                <label class="block text-sm font-medium text-slate-400 mb-1.5">Username</label>
                <input type="text" name="username" required class="w-full bg-slate-900 border border-slate-800 rounded-xl p-3.5 text-white focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition">
            </div>
            <div>
                <label class="block text-sm font-medium text-slate-400 mb-1.5">Password</label>
                <input type="password" name="password" required class="w-full bg-slate-900 border border-slate-800 rounded-xl p-3.5 text-white focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition">
            </div>
            <button class="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-bold py-3.5 rounded-xl transition shadow-lg shadow-indigo-500/20">Sign in</button>
        </form>
        <p class="text-center mt-8 text-slate-500 text-sm">New to Vigil? <a href="/register" class="text-indigo-400 hover:text-indigo-300 font-medium">Create account</a></p>
    """
    return render_template_string(AUTH_LAYOUT.replace("CONTENT_PLACEHOLDER", form_html))


@app.route('/register', methods=['GET', 'POST'])
def register():
    msg = ""
    if request.method == 'POST':
        u = request.form['username'];
        p = request.form['password']
        h = generate_password_hash(p);
        k = "sk_live_" + secrets.token_hex(16)
        try:
            conn = get_db_connection();
            cur = conn.cursor()
            cur.execute("INSERT INTO users_v5 (username, password_hash, api_key) VALUES (%s, %s, %s) RETURNING id",
                        (u, h, k))
            uid = cur.fetchone()[0];
            conn.commit();
            cur.close();
            conn.close()
            user = User(id=uid, username=u, password_hash=h, discord_webhook=None, api_key=k)
            login_user(user);
            return redirect(url_for('settings'))
        except:
            msg = "Username already exists."

    form_html = f"""
        <h2 class="text-3xl font-bold text-white mb-2">Create account</h2>
        <p class="text-slate-400 mb-8">Start protecting your organization's data.</p>
        {'<div class="bg-red-500/10 text-red-400 p-3 rounded-lg mb-6 text-sm border border-red-500/20">' + msg + '</div>' if msg else ''}
        <form method="POST" class="space-y-5">
            <div>
                <label class="block text-sm font-medium text-slate-400 mb-1.5">Username</label>
                <input type="text" name="username" required class="w-full bg-slate-900 border border-slate-800 rounded-xl p-3.5 text-white focus:outline-none focus:border-indigo-500 transition">
            </div>
            <div>
                <label class="block text-sm font-medium text-slate-400 mb-1.5">Password</label>
                <input type="password" name="password" required class="w-full bg-slate-900 border border-slate-800 rounded-xl p-3.5 text-white focus:outline-none focus:border-indigo-500 transition">
            </div>
            <button class="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-bold py-3.5 rounded-xl transition shadow-lg shadow-indigo-500/20">Create Account</button>
        </form>
        <p class="text-center mt-8 text-slate-500 text-sm">Already a member? <a href="/login" class="text-indigo-400 hover:text-indigo-300 font-medium">Log in</a></p>
    """
    return render_template_string(AUTH_LAYOUT.replace("CONTENT_PLACEHOLDER", form_html))


@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection();
    cur = conn.cursor()
    cur.execute("SELECT * FROM transactions_v5 WHERE user_id = %s ORDER BY created_at DESC;", (current_user.id,))
    rows = cur.fetchall();
    cur.close();
    conn.close()

    # Catch flashed messages from simulate_leak errors
    flashes = ""
    # (Simple flash handling for string template)
    # In a real app we'd use proper templating, but this is a single-file drop.

    return render_template_string("<!DOCTYPE html><html lang='en'>" + BASE_HEAD + """
    <body class="bg-slate-950">
        <nav class="glass border-b border-slate-800 px-6 h-16 flex justify-between items-center sticky top-0 z-20">
            <div class="flex items-center gap-3"><div class="w-8 h-8 bg-indigo-600 rounded-lg flex items-center justify-center font-bold">V</div><span class="font-bold text-lg tracking-tight">VIGIL</span></div>
            <div class="flex gap-6 text-sm font-medium items-center">
                <a href="/settings" class="text-slate-400 hover:text-white transition">Settings</a>
                <a href="/logout" class="text-slate-400 hover:text-white transition">Log Out</a>
                <a href="/simulate_leak" class="bg-red-600 hover:bg-red-500 text-white px-4 py-2 rounded-lg transition font-bold shadow-lg shadow-red-900/20 flex items-center gap-2"><span>⚠️</span> Test Leak</a>
            </div>
        </nav>
        <main class="max-w-5xl mx-auto p-6 mt-8">
            <div class="flex justify-between items-end mb-8">
                <div><h2 class="text-2xl font-bold text-white">Security Feed</h2><p class="text-slate-400 text-sm">Real-time DLP monitoring.</p></div>
                <div class="flex items-center gap-2 px-3 py-1 rounded-full bg-green-500/10 border border-green-500/20 text-green-400 text-xs font-bold uppercase"><span class="w-2 h-2 bg-green-500 rounded-full animate-pulse"></span> System Active</div>
            </div>

            {% if not rows %}
            <div class="text-center py-24 rounded-3xl border border-dashed border-slate-800 bg-slate-900/30">
                <div class="text-6xl mb-6 opacity-50">🛡️</div>
                <h3 class="text-xl font-bold text-white mb-2">No Threats Detected</h3>
                <p class="text-slate-500 mb-8 max-w-sm mx-auto">Your system is monitoring for leaks. Try simulating an attack to test the firewall.</p>
                <a href="/simulate_leak" class="px-6 py-3 bg-indigo-600 text-white rounded-xl font-bold hover:bg-indigo-500 transition">Simulate Attack</a>
            </div>
            {% endif %}

            <div class="space-y-4">
                {% for row in rows %}
                <div class="bg-slate-900/80 rounded-xl p-5 border-l-[4px] shadow-sm hover:bg-slate-900 transition {{ 'border-red-500' if row[5] > 70 else 'border-green-500' }}">
                    <div class="flex justify-between items-start mb-3">
                        <div class="flex items-center gap-3">
                            <span class="font-bold text-white text-sm">{{ row[2] }}</span>
                            <span class="text-[10px] px-2 py-0.5 rounded uppercase font-black tracking-wider {{ 'bg-red-500/20 text-red-400' if row[4] == 'BLOCKED' else 'bg-green-500/20 text-green-400' }}">{{ row[4] }}</span>
                        </div>
                        <div class="text-slate-600 text-xs font-mono">{{ row[7].strftime('%H:%M:%S') }}</div>
                    </div>
                    <div class="bg-black/30 rounded p-3 mb-3 font-mono text-sm text-slate-300 border border-white/5 break-all">"{{ row[3] }}"</div>
                    <div class="flex items-center gap-2 text-xs">
                        <span class="text-slate-500 font-semibold">AI Analysis:</span>
                        <span class="font-bold {{ 'text-red-400' if row[5] > 70 else 'text-green-400' }}">{{ row[6] }} (Risk: {{ row[5] }})</span>
                    </div>
                </div>
                {% endfor %}
            </div>
        </main></body></html>
    """, user=current_user, rows=rows)


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
    <body class="bg-slate-950 flex items-center justify-center min-h-screen">
        <div class="bg-slate-900 p-8 rounded-2xl w-full max-w-2xl border border-slate-800 shadow-2xl">
            <h2 class="text-2xl font-bold text-white mb-8">⚙️ Configuration</h2>
            <div class="mb-8">
                <label class="block text-xs font-bold text-indigo-400 mb-3 uppercase tracking-wider">Your API Key</label>
                <div class="bg-black/50 p-4 rounded-xl font-mono text-green-400 break-all border border-slate-800 select-all text-sm">{{ user.api_key }}</div>
            </div>
            <form method="POST">
                <label class="block text-xs font-bold text-slate-500 mb-3 uppercase tracking-wider">Discord Webhook</label>
                <input type="text" name="webhook" value="{{ user.discord_webhook or '' }}" placeholder="https://discord.com/api/webhooks/..." class="w-full bg-black/30 border border-slate-700 rounded-xl p-4 text-white mb-6 focus:border-indigo-500 outline-none transition">
                <button class="bg-white text-slate-900 hover:bg-slate-200 px-8 py-4 rounded-xl font-bold w-full transition">Save Changes</button>
            </form>
            <div class="mt-6 text-center"><a href="/dashboard" class="text-slate-500 hover:text-white text-sm">Back to Dashboard</a></div>
        </div>
    </body></html>""", user=current_user)


@app.route('/simulate_leak')
@login_required
def simulate_leak():
    try:
        # 1. Internal AI Call
        source = "Intern_David"
        prompt = "Debug: const AWS_SECRET = 'AKIA_TEST_KEY_12345';"
        req_id = str(uuid.uuid4())[:8]

        score, reason = analyze_security_risk(prompt)
        status = "BLOCKED" if score > 70 else "ALLOWED"

        # 2. DB Insert
        conn = get_db_connection();
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO transactions_v5 (id, user_id, source, description, status, risk_score, risk_reason) VALUES (%s,%s,%s,%s,%s,%s,%s)",
            (req_id, current_user.id, source, prompt, status, score, reason))
        conn.commit();
        cur.close();
        conn.close()

        # 3. Alert
        if status == "BLOCKED":
            send_discord_alert(current_user.discord_webhook,
                               f"🚨 **VIGIL BLOCKED LEAK**\nUser: {source}\nScore: {score}", 15548997)

        return redirect(url_for('dashboard'))
    except Exception as e:
        # SAFETY CATCH: If anything fails, don't crash the server. Show error.
        print(f"Error in simulation: {e}")
        traceback.print_exc()
        return f"<h3>Simulation Failed</h3><p>Error: {e}</p><a href='/dashboard'>Back</a>"


@app.route('/logout')
@login_required
def logout_route(): logout_user(); return redirect(url_for('landing'))


@app.route('/v1/firewall', methods=['POST'])
def firewall_api(): return jsonify({"status": "active"})


if __name__ == '__main__': app.run(port=5000)