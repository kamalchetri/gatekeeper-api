import os
import smtplib
from email.mime.text import MIMEText
from flask import Flask, request, jsonify, render_template_string
import uuid

app = Flask(__name__)

# --- CONFIGURATION ---
# Load secrets from Render
EMAIL_USER = os.environ.get('EMAIL_USER')
EMAIL_PASS = os.environ.get('EMAIL_PASS')

API_KEYS = {"sk_live_12345": "Bank of America Bot"}
transactions = {}


def send_email(transaction_id, status):
    """Sends a real email without crashing the server."""
    if not EMAIL_USER or not EMAIL_PASS:
        print("⚠️ Email secrets missing. Skipping.")
        return False

    try:
        subject = f"Gatekeeper Update: {status}"
        body = f"Transaction {transaction_id} has been {status} by the Manager."

        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = EMAIL_USER
        msg['To'] = EMAIL_USER

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(EMAIL_USER, EMAIL_PASS)
            server.send_message(msg)
        print(f"✅ EMAIL SENT for {transaction_id}")
        return True
    except Exception as e:
        print(f"❌ EMAIL FAILED: {e}")
        return False


def check_auth():
    return request.headers.get('X-API-KEY') in API_KEYS


@app.route('/')
def dashboard():
    # V1.0 Professional Dashboard (Clean Blue/Green Theme)
    html = """
    <meta http-equiv="refresh" content="5">
    <style>
        body{font-family:'Segoe UI', sans-serif; padding:2rem; text-align:center; background:#f0f2f5; color:#333;}
        .card{background:white; padding:25px; margin:20px auto; max-width:500px; border-radius:12px; box-shadow:0 4px 6px rgba(0,0,0,0.1);}
        .btn{padding:12px 24px; border:none; border-radius:6px; cursor:pointer; font-weight:bold; font-size:16px; margin:5px;}
        .approve{background:#2ecc71; color:white;}
        .reject{background:#e74c3c; color:white;}
        .status{font-weight:bold; font-size:18px;}
    </style>

    <h1>🛡️ Gatekeeper V1.0</h1>
    <p style="color:#777;">System Online • Ready for Requests</p>

    {% for id, data in db.items() %}
        <div class="card">
            <h3 style="margin-top:0;">Request: {{ data.source }}</h3>
            <p style="font-size:1.1em;">{{ data.description }}</p>
            <hr style="border:0; border-top:1px solid #eee; margin:20px 0;">

            {% if data.status == 'PENDING' %}
                <a href="/approve/{{ id }}"><button class="btn approve">✅ APPROVE</button></a>
                <a href="/reject/{{ id }}"><button class="btn reject">❌ REJECT</button></a>
            {% else %}
                <p class="status" style="color:{{ 'green' if data.status == 'APPROVED' else 'red' }}">
                    {{ data.status }}
                </p>
                <p style="font-size:0.9em; color:#888;">Action Logged & Email Sent</p>
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
    # SAFETY CHECK (The Anti-Crash Logic)
    if req_id not in transactions:
        return "<h3>⚠️ Transaction Expired</h3><p>The server restarted. Please run the Client Bot again.</p>"

    transactions[req_id]["status"] = "APPROVED"
    # Send Email in background
    send_email(req_id, "APPROVED")

    return "<h3>Authorized.</h3><p>Email sent.</p><script>setTimeout(()=>window.location.href='/', 1500)</script>"


@app.route('/reject/<req_id>')
def reject(req_id):
    if req_id not in transactions:
        return "<h3>⚠️ Transaction Expired</h3>"

    transactions[req_id]["status"] = "REJECTED"
    send_email(req_id, "REJECTED")
    return "<h3>Rejected.</h3><script>setTimeout(()=>window.location.href='/', 1500)</script>"


if __name__ == '__main__':
    app.run(port=5000)