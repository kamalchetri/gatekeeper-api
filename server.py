import os
import smtplib
from email.mime.text import MIMEText
from flask import Flask, request, jsonify, render_template_string
import uuid

app = Flask(__name__)

# 1. LOAD SECRETS FROM RENDER VAULT
# If we are on your laptop (where secrets don't exist), these might be None.
EMAIL_USER = os.environ.get('EMAIL_USER')
EMAIL_PASS = os.environ.get('EMAIL_PASS')

# 2. VALID API KEYS
API_KEYS = {
    "sk_live_12345": "Bank of America Bot",
}

transactions = {}


def send_email_notification(transaction_id, status):
    """
    This function logs into Gmail and sends a real email.
    """
    if not EMAIL_USER or not EMAIL_PASS:
        print("❌ Email secrets missing. Skipping email.")
        return

    try:
        msg = MIMEText(f"Your transaction {transaction_id} has been {status}.")
        msg['Subject'] = f"Transaction {status}: {transaction_id}"
        msg['From'] = EMAIL_USER
        msg['To'] = EMAIL_USER  # Sending it to yourself for the test

        # Connect to Gmail Server
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(EMAIL_USER, EMAIL_PASS)
            server.send_message(msg)
        print("✅ EMAIL SENT SUCCESSFULLY.")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")


def check_auth():
    key = request.headers.get('X-API-KEY')
    return key in API_KEYS


@app.route('/')
def dashboard():
    html = """
    <meta http-equiv="refresh" content="5">
    <style>body{font-family:sans-serif; padding:2rem; text-align:center; background:#f4f4f9;}</style>
    <h1>🛡️ Gatekeeper HQ</h1>

    {% for id, data in db.items() %}
        <div style="background:white; padding:20px; margin:20px auto; max-width:500px; border-radius:10px; border: 1px solid #ddd;">
            <h3>⚠️ Request from: {{ data.source }}</h3>
            <p>{{ data.description }}</p>

            {% if data.status == 'PENDING' %}
                <a href="/approve/{{ id }}"><button style="background:green; color:white; padding:15px; border:none; cursor:pointer;">✅ APPROVE & EMAIL</button></a>
                <a href="/reject/{{ id }}"><button style="background:red; color:white; padding:15px; border:none; cursor:pointer;">❌ REJECT</button></a>
            {% else %}
                <p>Status: <b style="color:green">{{ data.status }}</b></p>
                <p style="font-size:12px">✉️ Email Notification Sent</p>
            {% endif %}
        </div>
    {% endfor %}
    """
    return render_template_string(html, db=transactions)


@app.route('/api/request', methods=['POST'])
def create_request():
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    req_id = str(uuid.uuid4())[:8]
    transactions[req_id] = {
        "source": API_KEYS[request.headers.get('X-API-KEY')],
        "description": data.get("description"),
        "status": "PENDING"
    }
    return jsonify({"id": req_id})


@app.route('/api/check/<req_id>')
def check_status(req_id):
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401
    if req_id in transactions:
        return jsonify({"status": transactions[req_id]["status"]})
    return jsonify({"status": "UNKNOWN"})


@app.route('/approve/<req_id>')
def approve(req_id):
    transactions[req_id]["status"] = "APPROVED"
    # TRIGGER THE REAL WORLD ACTION
    send_email_notification(req_id, "APPROVED")
    return "Authorized. Email Sent."


@app.route('/reject/<req_id>')
def reject(req_id):
    transactions[req_id]["status"] = "REJECTED"
    # TRIGGER THE REAL WORLD ACTION
    send_email_notification(req_id, "REJECTED")
    return "Rejected. Email Sent."


if __name__ == '__main__':
    app.run(port=5000)