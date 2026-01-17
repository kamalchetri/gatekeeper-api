import uuid
import datetime
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

# --- DATABASE ---
API_KEYS = {"sk_live_12345": "Bank of America Bot"}
transactions = {}
inbox = []  # <--- WE ARE BUILDING OUR OWN EMAIL SERVER


def check_auth():
    return request.headers.get('X-API-KEY') in API_KEYS


@app.route('/')
def dashboard():
    html = """
    <meta http-equiv="refresh" content="5">
    <style>
        body{font-family:'Segoe UI', sans-serif; padding:2rem; text-align:center; background:#f4f4f9; color:#333;}
        .card{background:white; padding:25px; margin:20px auto; max-width:500px; border-radius:12px; box-shadow:0 4px 6px rgba(0,0,0,0.1);}
        .btn{padding:10px 20px; border:none; border-radius:6px; cursor:pointer; font-weight:bold; margin:5px;}
        .inbox-link{display:inline-block; margin-top:20px; text-decoration:none; color:#007bff; font-weight:bold;}
    </style>

    <h1>🛡️ Gatekeeper HQ</h1>
    <a href="/inbox" class="inbox-link">📨 View Sent Emails ({{ inbox_count }})</a>

    {% for id, data in db.items() %}
        <div class="card">
            <h3 style="margin-top:0;">{{ data.source }}</h3>
            <p>{{ data.description }}</p>
            <hr style="border:0; border-top:1px solid #eee; margin:20px 0;">

            {% if data.status == 'PENDING' %}
                <a href="/approve/{{ id }}"><button class="btn" style="background:#2ecc71; color:white;">✅ APPROVE</button></a>
                <a href="/reject/{{ id }}"><button class="btn" style="background:#e74c3c; color:white;">❌ REJECT</button></a>
            {% else %}
                <p style="color:{{ 'green' if data.status == 'APPROVED' else 'red' }}">
                    <b>{{ data.status }}</b>
                </p>
                <p style="font-size:0.8em; color:gray;">Notification sent to Inbox</p>
            {% endif %}
        </div>
    {% endfor %}
    """
    return render_template_string(html, db=transactions, inbox_count=len(inbox))


@app.route('/inbox')
def view_inbox():
    # THIS IS YOUR NEW INTERNAL EMAIL VIEWER
    html = """
    <style>
        body{font-family:'Segoe UI', sans-serif; padding:2rem; background:#fff; max-width:600px; margin:0 auto;}
        .email{border:1px solid #ddd; padding:20px; margin-bottom:15px; border-radius:8px; border-left:5px solid #007bff;}
        .time{color:#888; font-size:0.8em;}
        h1{border-bottom:2px solid #eee; padding-bottom:10px;}
        .back{text-decoration:none; color:#333; font-weight:bold;}
    </style>
    <a href="/" class="back">← Back to Dashboard</a>
    <h1>📨 System Outbox</h1>

    {% if not emails %}
        <p>No emails sent yet.</p>
    {% endif %}

    {% for email in emails|reverse %}
        <div class="email">
            <div class="time">{{ email.time }}</div>
            <h3>{{ email.subject }}</h3>
            <p>{{ email.body }}</p>
        </div>
    {% endfor %}
    """
    return render_template_string(html, emails=inbox)


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

    # SAVE EMAIL TO INTERNAL INBOX
    inbox.append({
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "subject": f"Transaction {req_id} Approved",
        "body": f"The manager has authorized the transaction {req_id} from {transactions[req_id]['source']}."
    })

    return "<h3>Authorized.</h3><p>Notification sent to Inbox.</p><script>setTimeout(()=>window.location.href='/', 1000)</script>"


@app.route('/reject/<req_id>')
def reject(req_id):
    if req_id not in transactions: return "<h3>Expired</h3>"

    transactions[req_id]["status"] = "REJECTED"

    inbox.append({
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "subject": f"Transaction {req_id} Rejected",
        "body": "The manager has rejected this request."
    })

    return "<h3>Rejected.</h3><script>setTimeout(()=>window.location.href='/', 1000)</script>"


if __name__ == '__main__':
    app.run(port=5000)