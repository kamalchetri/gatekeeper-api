import os
import smtplib
import threading
from email.mime.text import MIMEText
from flask import Flask, request, jsonify, render_template_string
import uuid

app = Flask(__name__)

# --- CONFIGURATION ---
EMAIL_USER = os.environ.get('EMAIL_USER')
EMAIL_PASS = os.environ.get('EMAIL_PASS')

API_KEYS = {"sk_live_12345": "Bank of America Bot"}
transactions = {}


def send_email_background(transaction_id, status):
    print(f"📧 DEBUG: Starting email thread for {transaction_id}")

    if not EMAIL_USER or not EMAIL_PASS:
        print("❌ ERROR: Secrets missing.")
        return

    try:
        subject = f"Gatekeeper Alert: {status}"
        body = f"Transaction {transaction_id} has been {status}."
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = EMAIL_USER
        msg['To'] = EMAIL_USER

        # --- DEBUG MODE ---
        print("🔌 Connecting to Gmail (Port 587) with 10s Timeout...")

        # 1. Connect with Timeout
        server = smtplib.SMTP('smtp.gmail.com', 587, timeout=10)

        # 2. Turn on "Verbose" logging (Prints the hidden conversation)
        server.set_debuglevel(1)

        print("👋 Saying Hello (EHLO)...")
        server.ehlo()

        print("🔒 Starting Encryption (STARTTLS)...")
        server.starttls()

        print("👋 Saying Hello Again (EHLO)...")
        server.ehlo()

        print("🔑 Logging in...")
        server.login(EMAIL_USER, EMAIL_PASS)

        print("📨 Sending Message...")
        server.send_message(msg)

        server.quit()
        print(f"✅ EMAIL SENT SUCCESSFULLY for {transaction_id}")

    except Exception as e:
        # This will now print the EXACT error (Timeout, Auth, etc)
        print(f"❌ EMAIL FAILED: {e}")


def check_auth():
    return request.headers.get('X-API-KEY') in API_KEYS


@app.route('/')
def dashboard():
    html = """
    <meta http-equiv="refresh" content="5">
    <style>body{font-family:sans-serif; padding:2rem; text-align:center; background:#fff8e1;}</style>
    <h1>🛡️ Gatekeeper Debugger</h1>

    {% for id, data in db.items() %}
        <div style="background:white; padding:20px; margin:20px auto; max-width:500px; border-radius:10px; border: 1px solid #ddd;">
            <h3>Request: {{ data.source }}</h3>
            <p>{{ data.description }}</p>
            {% if data.status == 'PENDING' %}
                <a href="/approve/{{ id }}"><button style="background:green; color:white; padding:15px;">✅ APPROVE</button></a>
            {% else %}
                <p>Status: <b>{{ data.status }}</b></p>
            {% endif %}
        </div>
    {% endfor %}
    """
    return render_template_string(html, db=transactions)


@app.route('/api/request', methods=['POST'])
def create_request():
    if not check_auth(): return jsonify({"error": "Unauthorized"}), 401
    req_id = str(uuid.uuid4())[:8]
    transactions[req_id] = {
        "source": API_KEYS[request.headers.get('X-API-KEY')],
        "description": request.json.get("description"),
        "status": "PENDING"
    }
    return jsonify({"id": req_id})


@app.route('/api/check/<req_id>')
def check_status(req_id):
    if req_id in transactions: return jsonify({"status": transactions[req_id]["status"]})
    return jsonify({"status": "UNKNOWN"})


@app.route('/approve/<req_id>')
def approve(req_id):
    if req_id not in transactions: return "<h3>Expired</h3>"
    transactions[req_id]["status"] = "APPROVED"
    threading.Thread(target=send_email_background, args=(req_id, "APPROVED")).start()
    return "<h3>Authorized.</h3><p>Check Render Logs for 'send: ...' messages.</p><script>setTimeout(()=>window.location.href='/', 2000)</script>"


if __name__ == '__main__':
    app.run(port=5000)