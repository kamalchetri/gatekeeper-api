import os
import uuid
import psycopg2
import requests
from flask import Flask, request, jsonify, render_template_string, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'default_secret_key')

# --- CONFIGURATION ---
DISCORD_URL = os.environ.get('DISCORD_WEBHOOK_URL')
DB_URL = os.environ.get('DATABASE_URL')


# --- DB HELPERS ---
def get_db_connection():
    if not DB_URL: raise ValueError("DATABASE_URL is missing")
    conn = psycopg2.connect(DB_URL)
    return conn


def init_db():
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # 1. NEW Users Table (v2 forces a fresh start)
        cur.execute("""
                    CREATE TABLE IF NOT EXISTS users_v2
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

        # 2. NEW Transactions Table (v2)
        cur.execute("""
                    CREATE TABLE IF NOT EXISTS transactions_v2
                    (
                        id
                        VARCHAR
                    (
                        10
                    ) PRIMARY KEY,
                        user_id INTEGER REFERENCES users_v2
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
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        );
                    """)

        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"❌ DB Init Error: {e}")


if DB_URL: init_db()

# --- LOGIN SETUP ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash


@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    # Note: Reading from users_v2 now
    cur.execute("SELECT * FROM users_v2 WHERE id = %s", (user_id,))
    res = cur.fetchone()
    cur.close()
    conn.close()
    if res: return User(id=res[0], username=res[1], password_hash=res[2])
    return None


# --- ROUTES ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    message = ""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_pw = generate_password_hash(password)

        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("INSERT INTO users_v2 (username, password_hash) VALUES (%s, %s) RETURNING id",
                        (username, hashed_pw))
            user_id = cur.fetchone()[0]
            conn.commit()
            cur.close()
            conn.close()

            user = User(id=user_id, username=username, password_hash=hashed_pw)
            login_user(user)
            return redirect(url_for('dashboard'))
        except psycopg2.errors.UniqueViolation:
            message = "❌ Username already taken."
        except Exception as e:
            message = f"❌ Error: {e}"

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Sign Up | Gatekeeper</title>
        <style>
            body { font-family: system-ui, sans-serif; background: #f0f2f5; height: 100vh; display: flex; align-items: center; justify-content: center; margin: 0; }
            .card { background: white; padding: 40px; border-radius: 16px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); width: 100%; max-width: 320px; text-align: center; }
            input { width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #ddd; border-radius: 8px; box-sizing: border-box; }
            button { width: 100%; padding: 12px; margin-top: 15px; background: #2ecc71; color: white; border: none; border-radius: 8px; font-weight: bold; cursor: pointer; }
            .link { display: block; margin-top: 15px; color: #007bff; text-decoration: none; font-size: 0.9em; }
            .error { color: red; margin-bottom: 10px; }
        </style>
    </head>
    <body>
        <div class="card">
            <h2>Create Account</h2>
            <div class="error">{{ message }}</div>
            <form method="POST">
                <input type="text" name="username" placeholder="Choose Username" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Sign Up</button>
            </form>
            <a href="/login" class="link">Already have an account? Login</a>
        </div>
    </body>
    </html>
    """
    return render_template_string(html, message=message)


@app.route('/login', methods=['GET', 'POST'])
def login():
    message = ""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users_v2 WHERE username = %s", (username,))
        user_data = cur.fetchone()
        cur.close()
        conn.close()
        if user_data and check_password_hash(user_data[2], password):
            user = User(id=user_data[0], username=user_data[1], password_hash=user_data[2])
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            message = "❌ Invalid Credentials"

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Login | Gatekeeper</title>
        <style>
            body { font-family: system-ui, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); height: 100vh; display: flex; align-items: center; justify-content: center; margin: 0; }
            .card { background: white; padding: 40px; border-radius: 16px; box-shadow: 0 10px 25px rgba(0,0,0,0.2); width: 100%; max-width: 320px; text-align: center; }
            input { width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #e2e8f0; border-radius: 8px; box-sizing: border-box; }
            button { width: 100%; padding: 12px; margin-top: 15px; background: #667eea; color: white; border: none; border-radius: 8px; font-weight: bold; cursor: pointer; }
            .link { display: block; margin-top: 15px; color: #667eea; text-decoration: none; font-size: 0.9em; }
        </style>
    </head>
    <body>
        <div class="card">
            <span style="font-size:40px;">🛡️</span>
            <h2>Welcome Back</h2>
            <div style="color:red; margin-bottom:10px;">{{ message }}</div>
            <form method="POST">
                <input type="text" name="username" placeholder="Username" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Sign In</button>
            </form>
            <a href="/register" class="link">New? Create an Account</a>
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
    # 🔒 ISOLATION: Reading from transactions_v2
    cur.execute("SELECT * FROM transactions_v2 WHERE user_id = %s ORDER BY created_at DESC;", (current_user.id,))
    rows = cur.fetchall()
    cur.close()
    conn.close()

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Dashboard</title>
        <style>
            :root { --primary: #667eea; --bg: #f7fafc; }
            body { font-family: system-ui, sans-serif; background: var(--bg); margin: 0; padding-bottom: 40px; }
            .navbar { background: white; padding: 15px 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); display: flex; justify-content: space-between; align-items: center; }
            .container { max-width: 1000px; margin: 30px auto; padding: 0 20px; }
            .card { background: white; padding: 20px; border-radius: 12px; box-shadow: 0 2px 5px rgba(0,0,0,0.05); margin-bottom: 20px; }
            .demo-btn { background: #333; color: white; padding: 10px 20px; border-radius: 20px; text-decoration: none; font-size: 0.9em; font-weight: bold; }
            .status-pill { padding: 5px 10px; border-radius: 15px; font-size: 0.8em; font-weight: bold; }
            .approved { background: #c6f6d5; color: #276749; }
            .rejected { background: #fed7d7; color: #9b2c2c; }
            .btn { padding: 8px 16px; border-radius: 6px; text-decoration: none; color: white; font-weight: bold; margin-right: 5px; }
        </style>
    </head>
    <body>
        <nav class="navbar">
            <div><b>Gatekeeper</b> | {{ user.username }}</div>
            <div>
                <a href="/simulate_demo" class="demo-btn">⚡ Test Alert</a>
                <a href="/logout" style="margin-left:15px; text-decoration:none; color:red;">Log Out</a>
            </div>
        </nav>

        <div class="container">
            {% if not rows %}
                <div style="text-align:center; margin-top:50px; color:#888;">
                    <h3>No requests yet.</h3>
                    <p>Click "⚡ Test Alert" above to simulate a bot request!</p>
                </div>
            {% endif %}

            {% for row in rows %}
            <div class="card">
                <h3>{{ row[2] }}</h3>
                <p>{{ row[3] }}</p>

                {% if row[4] == 'PENDING' %}
                    <a href="/approve/{{ row[0] }}" class="btn" style="background:#48bb78;">Approve</a>
                    <a href="/reject/{{ row[0] }}" class="btn" style="background:#f56565;">Reject</a>
                {% else %}
                    <span class="status-pill {{ 'approved' if row[4] == 'APPROVED' else 'rejected' }}">{{ row[4] }}</span>
                {% endif %}
            </div>
            {% endfor %}
        </div>
    </body>
    </html>
    """
    return render_template_string(html, rows=rows, user=current_user)


@app.route('/simulate_demo')
@login_required
def simulate_demo():
    conn = get_db_connection()
    cur = conn.cursor()
    req_id = str(uuid.uuid4())[:8]
    # Inserting into transactions_v2
    cur.execute("INSERT INTO transactions_v2 (id, user_id, source, description, status) VALUES (%s, %s, %s, %s, %s)",
                (req_id, current_user.id, "Demo Bot", "Requesting $500 for Server Costs", "PENDING"))
    conn.commit()
    cur.close()
    conn.close()
    return redirect(url_for('dashboard'))


@app.route('/approve/<req_id>')
@login_required
def approve(req_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE transactions_v2 SET status = 'APPROVED' WHERE id = %s AND user_id = %s",
                (req_id, current_user.id))
    conn.commit()
    cur.close()
    conn.close()
    return redirect(url_for('dashboard'))


@app.route('/reject/<req_id>')
@login_required
def reject(req_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE transactions_v2 SET status = 'REJECTED' WHERE id = %s AND user_id = %s",
                (req_id, current_user.id))
    conn.commit()
    cur.close()
    conn.close()
    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    app.run(port=5000)