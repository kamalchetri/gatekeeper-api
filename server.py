import os
import uuid
import psycopg2
from flask import Flask, request, jsonify, render_template_string, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'default_secret_key')  # Needed for sessions

# --- LOGIN CONFIGURATION ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Where to send unauth users

# --- DATABASE CONNECTION ---
DB_URL = os.environ.get('DATABASE_URL')


def get_db_connection():
    if not DB_URL: raise ValueError("DATABASE_URL is missing")
    conn = psycopg2.connect(DB_URL)
    return conn


# --- USER CLASS (Required by Flask-Login) ---
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

        # 1. Transactions Table
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

        # 2. Users Table (For Login)
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

        # 3. Create Default Admin (if not exists)
        cur.execute("SELECT * FROM users WHERE username = 'admin'")
        if not cur.fetchone():
            print("👤 Creating default admin user...")
            hashed_pw = generate_password_hash("admin123")  # <--- DEFAULT PASSWORD
            cur.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", ('admin', hashed_pw))

        conn.commit()
        cur.close()
        conn.close()
        print("✅ Database & Admin Ready.")
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
            message = "❌ Invalid Username or Password"

    html = """
    <style>
        body{font-family:'Segoe UI', sans-serif; display:flex; justify-content:center; align-items:center; height:100vh; background:#f0f2f5; margin:0;}
        .login-card{background:white; padding:40px; border-radius:10px; box-shadow:0 4px 10px rgba(0,0,0,0.1); width:300px; text-align:center;}
        input{width:100%; padding:10px; margin:10px 0; border:1px solid #ddd; border-radius:5px; box-sizing:border-box;}
        button{width:100%; padding:10px; background:#007bff; color:white; border:none; border-radius:5px; cursor:pointer; font-weight:bold;}
        button:hover{background:#0056b3;}
        .error{color:red; margin-bottom:10px;}
    </style>
    <div class="login-card">
        <h2>🔒 Gatekeeper Login</h2>
        <div class="error">{{ message }}</div>
        <form method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
    </div>
    """
    return render_template_string(html, message=message)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/')
@login_required  # <--- THIS PROTECTS THE DASHBOARD
def dashboard():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM transactions ORDER BY created_at DESC;")
    rows = cur.fetchall()
    cur.close()
    conn.close()

    html = """
    <meta http-equiv="refresh" content="5">
    <style>
        body{font-family:'Segoe UI', sans-serif; padding:2rem; text-align:center; background:#f4f4f9;}
        .card{background:white; padding:25px; margin:20px auto; max-width:500px; border-radius:12px; box-shadow:0 4px 6px rgba(0,0,0,0.1);}
        .btn{padding:10px 20px; border:none; border-radius:6px; cursor:pointer; font-weight:bold; margin:5px;}
        .logout{position:absolute; top:20px; right:20px; text-decoration:none; color:#e74c3c; font-weight:bold;}
    </style>

    <a href="/logout" class="logout">Log Out</a>
    <h1>🛡️ Gatekeeper Admin</h1>
    <p>Logged in as: <b>{{ user.username }}</b></p>

    {% for row in rows %}
        <div class="card">
            <h3>{{ row[1] }}</h3>
            <p>{{ row[2] }}</p>
            {% if row[3] == 'PENDING' %}
                <a href="/approve/{{ row[0] }}"><button class="btn" style="background:#2ecc71; color:white;">✅ APPROVE</button></a>
                <a href="/reject/{{ row[0] }}"><button class="btn" style="background:#e74c3c; color:white;">❌ REJECT</button></a>
            {% else %}
                <p>Status: <b>{{ row[3] }}</b></p>
            {% endif %}
            <p style="font-size:0.7em; color:#888;">ID: {{ row[0] }}</p>
        </div>
    {% endfor %}
    """
    return render_template_string(html, rows=rows, user=current_user)


@app.route('/approve/<req_id>')
@login_required  # <--- PROTECTED
def approve(req_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE transactions SET status = 'APPROVED' WHERE id = %s", (req_id,))
    conn.commit()
    cur.close()
    conn.close()
    return redirect(url_for('dashboard'))


@app.route('/reject/<req_id>')
@login_required  # <--- PROTECTED
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
    # API IS NOT PASSWORD PROTECTED (It uses API Key)
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