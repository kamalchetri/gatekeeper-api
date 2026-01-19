import os
import uuid
import psycopg2
from flask import Flask, request, jsonify, render_template_string, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'default_secret_key')

# --- LOGIN CONFIGURATION ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- DATABASE CONNECTION ---
DB_URL = os.environ.get('DATABASE_URL')


def get_db_connection():
    if not DB_URL: raise ValueError("DATABASE_URL is missing")
    conn = psycopg2.connect(DB_URL)
    return conn


# --- USER CLASS ---
class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash


@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    res = cur.fetchone()
    cur.close()
    conn.close()
    if res: return User(id=res[0], username=res[1], password_hash=res[2])
    return None


def init_db():
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Transactions Table
        cur.execute("""
                    CREATE TABLE IF NOT EXISTS transactions
                    (
                        id
                        VARCHAR
                    (
                        10
                    ) PRIMARY KEY,
                        source VARCHAR
                    (
                        100
                    ),
                        description TEXT,
                        status VARCHAR
                    (
                        20
                    ),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        );
                    """)

        # Users Table
        cur.execute("""
                    CREATE TABLE IF NOT EXISTS users
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
                        password_hash TEXT NOT NULL
                        );
                    """)

        # Default Admin
        cur.execute("SELECT * FROM users WHERE username = 'admin'")
        if not cur.fetchone():
            hashed_pw = generate_password_hash("admin123")
            cur.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", ('admin', hashed_pw))

        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"❌ DB Init Error: {e}")


if DB_URL: init_db()

API_KEYS = {"sk_live_12345": "Bank of America Bot"}


def check_api_auth():
    return request.headers.get('X-API-KEY') in API_KEYS


# --- ROUTES ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    message = ""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        user_data = cur.fetchone()
        cur.close()
        conn.close()

        if user_data and check_password_hash(user_data[2], password):
            user_obj = User(id=user_data[0], username=user_data[1], password_hash=user_data[2])
            login_user(user_obj)
            return redirect(url_for('dashboard'))
        else:
            message = "❌ Invalid Credentials"

    # --- NEW DESIGNER LOGIN PAGE ---
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Login | Gatekeeper</title>
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                margin: 0;
            }
            .login-card {
                background: white;
                padding: 40px;
                border-radius: 16px;
                box-shadow: 0 10px 25px rgba(0,0,0,0.2);
                width: 100%;
                max-width: 320px;
                text-align: center;
            }
            h2 { margin-top: 0; color: #333; }
            input {
                width: 100%;
                padding: 12px;
                margin: 8px 0;
                border: 1px solid #e2e8f0;
                border-radius: 8px;
                box-sizing: border-box;
                font-size: 16px;
            }
            button {
                width: 100%;
                padding: 12px;
                margin-top: 15px;
                background: #667eea;
                color: white;
                border: none;
                border-radius: 8px;
                font-size: 16px;
                font-weight: bold;
                cursor: pointer;
                transition: background 0.3s;
            }
            button:hover { background: #5a67d8; }
            .error { color: #e53e3e; margin-bottom: 15px; font-size: 0.9em; }
            .brand { font-size: 40px; margin-bottom: 10px; display: block; }
        </style>
    </head>
    <body>
        <div class="login-card">
            <span class="brand">🛡️</span>
            <h2>Welcome Back</h2>
            <div class="error">{{ message }}</div>
            <form method="POST">
                <input type="text" name="username" placeholder="Username" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Sign In</button>
            </form>
        </div>
    </body>
    </html>
    """
    return render_template_string(html, message=message)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/')
@login_required
def dashboard():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM transactions ORDER BY created_at DESC;")
    rows = cur.fetchall()
    cur.close()
    conn.close()

    # --- NEW RESPONSIVE DASHBOARD ---
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta http-equiv="refresh" content="5">
        <title>Dashboard | Gatekeeper</title>
        <style>
            :root { --primary: #667eea; --bg: #f7fafc; --text: #2d3748; }
            body {
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                background: var(--bg);
                color: var(--text);
                margin: 0;
                padding-bottom: 40px;
            }

            /* Navbar */
            .navbar {
                background: white;
                padding: 15px 20px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.05);
                display: flex;
                justify-content: space-between;
                align-items: center;
                position: sticky;
                top: 0;
                z-index: 100;
            }
            .logo { font-weight: bold; font-size: 1.2rem; display: flex; align-items: center; gap: 8px; }
            .logout-btn {
                text-decoration: none;
                color: #e53e3e;
                font-weight: 600;
                font-size: 0.9rem;
                padding: 8px 12px;
                border-radius: 6px;
                transition: background 0.2s;
            }
            .logout-btn:hover { background: #fff5f5; }

            /* Grid Layout */
            .container {
                max-width: 1000px;
                margin: 30px auto;
                padding: 0 20px;
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
                gap: 20px;
            }

            /* Cards */
            .card {
                background: white;
                padding: 24px;
                border-radius: 12px;
                box-shadow: 0 4px 6px rgba(0,0,0,0.02);
                border: 1px solid #edf2f7;
                transition: transform 0.2s, box-shadow 0.2s;
                display: flex;
                flex-direction: column;
                justify-content: space-between;
            }
            .card:hover { transform: translateY(-2px); box-shadow: 0 10px 15px rgba(0,0,0,0.05); }

            h3 { margin: 0 0 10px 0; font-size: 1.1rem; color: #1a202c; }
            .desc { color: #718096; line-height: 1.5; margin-bottom: 20px; flex-grow: 1; }
            .meta { font-size: 0.75rem; color: #a0aec0; margin-top: 15px; border-top: 1px solid #edf2f7; padding-top: 10px; }

            /* Buttons */
            .actions { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
            .btn {
                padding: 12px;
                border: none;
                border-radius: 8px;
                cursor: pointer;
                font-weight: 600;
                font-size: 0.9rem;
                transition: opacity 0.2s;
                width: 100%;
            }
            .btn:hover { opacity: 0.9; }
            .approve { background: #48bb78; color: white; }
            .reject { background: #f56565; color: white; }
            a { text-decoration: none; }

            /* Status Pills */
            .status-pill {
                display: inline-block;
                padding: 6px 12px;
                border-radius: 20px;
                font-size: 0.8rem;
                font-weight: 700;
                text-transform: uppercase;
                letter-spacing: 0.05em;
                width: fit-content;
            }
            .status-approved { background: #c6f6d5; color: #276749; }
            .status-rejected { background: #fed7d7; color: #9b2c2c; }
        </style>
    </head>
    <body>
        <nav class="navbar">
            <div class="logo">🛡️ Gatekeeper <span style="font-weight:normal; color:#718096; font-size:0.9em;">| {{ user.username }}</span></div>
            <a href="/logout" class="logout-btn">Log Out</a>
        </nav>

        <div class="container">
            {% for row in rows %}
            <div class="card">
                <div>
                    <h3>{{ row[1] }}</h3>
                    <div class="desc">{{ row[2] }}</div>
                </div>

                {% if row[3] == 'PENDING' %}
                    <div class="actions">
                        <a href="/approve/{{ row[0] }}"><button class="btn approve">Approve</button></a>
                        <a href="/reject/{{ row[0] }}"><button class="btn reject">Reject</button></a>
                    </div>
                {% else %}
                    <div class="status-pill {{ 'status-approved' if row[3] == 'APPROVED' else 'status-rejected' }}">
                        {{ row[3] }}
                    </div>
                {% endif %}

                <div class="meta">Transaction ID: {{ row[0] }}</div>
            </div>
            {% endfor %}
        </div>
    </body>
    </html>
    """
    return render_template_string(html, rows=rows, user=current_user)


@app.route('/approve/<req_id>')
@login_required
def approve(req_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE transactions SET status = 'APPROVED' WHERE id = %s", (req_id,))
    conn.commit()
    cur.close()
    conn.close()
    return redirect(url_for('dashboard'))


@app.route('/reject/<req_id>')
@login_required
def reject(req_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE transactions SET status = 'REJECTED' WHERE id = %s", (req_id,))
    conn.commit()
    cur.close()
    conn.close()
    return redirect(url_for('dashboard'))


@app.route('/api/request', methods=['POST'])
def create_request():
    if not check_api_auth(): return jsonify({"error": "Unauthorized"}), 401

    req_id = str(uuid.uuid4())[:8]
    source = API_KEYS[request.headers.get('X-API-KEY')]
    description = request.json.get("description")

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("INSERT INTO transactions (id, source, description, status) VALUES (%s, %s, %s, %s)",
                (req_id, source, description, "PENDING"))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"id": req_id})


@app.route('/api/check/<req_id>')
def check_status(req_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT status FROM transactions WHERE id = %s", (req_id,))
    res = cur.fetchone()
    cur.close()
    conn.close()
    if res: return jsonify({"status": res[0]})
    return jsonify({"status": "UNKNOWN"})


if __name__ == '__main__':
    app.run(port=5000)