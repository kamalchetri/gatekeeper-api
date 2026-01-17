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
    print(f"📧 STARTING EMAIL THREAD for {transaction_id}...")

    if not EMAIL_USER or not EMAIL_PASS:
        print("❌ ERROR: Email secrets are missing.")
        return

    try:
        subject = f"Gatekeeper Alert: {status}"
        body = f"Transaction {transaction_id} has been {status}."

        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = EMAIL_USER
        msg['To'] = EMAIL_USER

        # --- THE FIX: USE PORT 587 (TLS) INSTEAD OF 465 ---
        print("🔌 Connecting to Gmail via Port 587...")
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()  # Secure the connection manually
            server.login(EMAIL_USER, EMAIL_PASS)
            server.send_message(msg)

        print(f"✅ EMAIL SENT SUCCESSFULLY for {transaction_id}")

    except Exception as e:
        print(f"❌ EMAIL CRASHED: {e}")


def check_auth():
    return request.headers.get('X-API-KEY') in API_KEYS


@app.route('/')
def dashboard():
    html = """
    <meta http-equiv="refresh" content="5">
    <style>body{font-family:sans-serif; padding:2rem; text-align:center; background:#f0f2f5;}</style>
    <h1>🛡️ Gatekeeper V2 (TLS)</h1>

    {% for id, data in db.items() %}
        <div style="background:white; padding:20px; margin:20px auto; max-width:500px; border-radius:10px; border: 1px solid #ddd;">
            <h3>Request: {{ data.source }}</h3>
            <p>{{ data.description }}</p>

            {% if data.status == 'PENDING' %}
                <a href="/approve/{{ id }}"><button style="background:green; color:white; padding:15px; cursor:pointer;">✅ APPROVE</button></a>
                <a href="/reject/{{ id }}"><button style="background:red; color:white; padding:15px; cursor:pointer;">❌ REJECT</button></a>
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
    if req_id in transactions:
        return jsonify({"status": transactions[req_id]["status"]})
    return jsonify({"status": "UNKNOWN"})


@app.route('/approve/<req_id>')
def approve(req_id):
    if req_id not in transactions:
        return "<h3>⚠️ Transaction Expired</h3>"

    transactions[req_id]["status"] = "APPROVED"

    email_thread = threading.Thread(target=send_email_background, args=(req_id, "APPROVED"))
    email_thread.start()

    return "<h3>Authorized.</h3><p>Email sending in background...</p><script>setTimeout(()=>window.location.href='/', 1500)</script>"


@app.route('/reject/<req_id>')
def reject(req_id):
    if req_id not in transactions:
        return "<h3>⚠️ Transaction Expired</h3>"

    transactions[req_id]["status"] = "REJECTED"
    email_thread = threading.Thread(target=send_email_background, args=(req_id, "REJECTED"))
    email_thread.start()
    return "<h3>Rejected.</h3><script>setTimeout(()=>window.location.href='/', 1500)</script>"


if __name__ == '__main__':
    app.run(port=5000)