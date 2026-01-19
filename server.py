import os
import uuid
import psycopg2
import datetime
import sys
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

# --- STARTUP DIAGNOSTICS ---
# This section runs immediately when the server wakes up
print("🔍 SYSTEM DIAGNOSTICS STARTING...")

# 1. Get the URL
DB_URL = os.environ.get('DATABASE_URL')

# 2. Print what we found (we mask the password for safety)
if DB_URL is None:
    print("❌ FATAL ERROR: DATABASE_URL is None. The Environment Variable is missing.")
elif DB_URL == "":
    print("❌ FATAL ERROR: DATABASE_URL is Empty.")
else:
    masked_url = DB_URL.split('@')[-1]  # Hide password
    print(f"✅ FOUND DATABASE URL! Pointing to: ...@{masked_url}")

print("🔍 DIAGNOSTICS COMPLETE.")


# ---------------------------

def get_db_connection():
    # This will crash intentionally if URL is missing, so we see the error in logs
    if not DB_URL:
        raise ValueError("DATABASE_URL is missing")
    conn = psycopg2.connect(DB_URL)
    return conn


def init_db():
    if not DB_URL: return  # Skip if broken
    try:
        conn = get_db_connection()
        cur = conn.cursor()
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
        print("✅ TABLE CREATED SUCCESSFULLY.")
    except Exception as e:
        print(f"❌ DB INIT FAILED: {e}")


# Try to init immediately
if DB_URL:
    init_db()

API_KEYS = {"sk_live_12345": "Bank of America Bot"}


def check_auth():
    return request.headers.get('X-API-KEY') in API_KEYS


@app.route('/')
def dashboard():
    if not DB_URL: return "<h1>❌ Critical Error: DATABASE_URL missing. Check Logs.</h1>"

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM transactions ORDER BY created_at DESC;")
    rows = cur.fetchall()
    cur.close()
    conn.close()

    html = """
    <meta http-equiv="refresh" content="5">
    <style>body{font-family:sans-serif; padding:2rem; text-align:center;}</style>
    <h1>🛡️ Gatekeeper SQL</h1>
    {% for row in rows %}
        <div style="border:1px solid #ccc; padding:10px; margin:10px;">
            <h3>{{ row[1] }}</h3>
            <p>{{ row[2] }}</p>
            <p>Status: <b>{{ row[3] }}</b></p>
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
    if result: return jsonify({"status": result[0]})
    return jsonify({"status": "UNKNOWN"})


@app.route('/approve/<req_id>')
def approve(req_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE transactions SET status = 'APPROVED' WHERE id = %s", (req_id,))
    conn.commit()
    cur.close()
    conn.close()
    return "Authorized."


@app.route('/reject/<req_id>')
def reject(req_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE transactions SET status = 'REJECTED' WHERE id = %s", (req_id,))
    conn.commit()
    cur.close()
    conn.close()
    return "Rejected."


if __name__ == '__main__':
    app.run(port=5000)