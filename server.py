import os
import uuid
import psycopg2
import datetime
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

# 1. CONNECT TO DATABASE
DB_URL = os.environ.get('DATABASE_URL')


def get_db_connection():
    conn = psycopg2.connect(DB_URL)
    return conn


def init_db():
    """Creates the table if it doesn't exist."""
    conn = get_db_connection()
    cur = conn.cursor()
    # Create Transactions Table
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
    conn.commit()
    cur.close()
    conn.close()


# Run initialization immediately on startup
try:
    init_db()
    print("✅ Database connected and table ready.")
except Exception as e:
    print(f"❌ Database Error: {e}")

API_KEYS = {"sk_live_12345": "Bank of America Bot"}


def check_auth():
    return request.headers.get('X-API-KEY') in API_KEYS


@app.route('/')
def dashboard():
    conn = get_db_connection()
    cur = conn.cursor()
    # SELECT ALL from database (Newest first)
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
    </style>

    <h1>🛡️ Gatekeeper (SQL Edition)</h1>
    <p>Data is now stored permanently in PostgreSQL.</p>

    {% for row in rows %}
        <div class="card">
            <h3>{{ row[1] }}</h3> <p>{{ row[2] }}</p>   {% if row[3] == 'PENDING' %}
                <a href="/approve/{{ row[0] }}"><button class="btn" style="background:#2ecc71; color:white;">✅ APPROVE</button></a>
                <a href="/reject/{{ row[0] }}"><button class="btn" style="background:#e74c3c; color:white;">❌ REJECT</button></a>
            {% else %}
                <p>Status: <b>{{ row[3] }}</b></p>
            {% endif %}
            <p style="font-size:0.7em; color:#888;">ID: {{ row[0] }}</p>
        </div>
    {% endfor %}
    """
    return render_template_string(html, rows=rows)


@app.route('/api/request', methods=['POST'])
def create_request():
    if not check_auth(): return jsonify({"error": "Unauthorized"}), 401

    req_id = str(uuid.uuid4())[:8]
    source = API_KEYS[request.headers.get('X-API-KEY')]
    description = request.json.get("description")

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO transactions (id, source, description, status) VALUES (%s, %s, %s, %s)",
        (req_id, source, description, "PENDING")
    )
    conn.commit()
    cur.close()
    conn.close()

    return jsonify({"id": req_id})


@app.route('/api/check/<req_id>')
def check_status(req_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT status FROM transactions WHERE id = %s", (req_id,))
    result = cur.fetchone()
    cur.close()
    conn.close()

    if result:
        return jsonify({"status": result[0]})
    return jsonify({"status": "UNKNOWN"})


@app.route('/approve/<req_id>')
def approve(req_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE transactions SET status = 'APPROVED' WHERE id = %s", (req_id,))
    conn.commit()
    cur.close()
    conn.close()
    return "<h3>Authorized (Saved to DB).</h3><script>setTimeout(()=>window.location.href='/', 1000)</script>"


@app.route('/reject/<req_id>')
def reject(req_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE transactions SET status = 'REJECTED' WHERE id = %s", (req_id,))
    conn.commit()
    cur.close()
    conn.close()
    return "<h3>Rejected (Saved to DB).</h3><script>setTimeout(()=>window.location.href='/', 1000)</script>"


if __name__ == '__main__':
    app.run(port=5000)