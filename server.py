from flask import Flask, request, jsonify, render_template_string
import uuid

app = Flask(__name__)

# 1. THE VALID API KEYS (The "VIP List")
# In a real startup, this comes from a database.
API_KEYS = {
    "sk_live_12345": "Bank of America Bot",
    "sk_live_events": "Ticketmaster Bot"
}

transactions = {}


def check_auth():
    # Look for the Key in the "Headers" (The envelope of the request)
    key = request.headers.get('X-API-KEY')
    if key not in API_KEYS:
        return False
    return True


@app.route('/')
def dashboard():
    # Dashboard doesn't need a key (It's for you)
    html = """
    <meta http-equiv="refresh" content="5">
    <style>body{font-family:sans-serif; padding:2rem; text-align:center; background:#f4f4f9;}</style>
    <h1>🛡️ Gatekeeper HQ</h1>

    {% for id, data in db.items() %}
        <div style="background:white; padding:20px; margin:20px auto; max-width:500px; border-radius:10px; border: 1px solid #ddd;">
            <h3>⚠️ Request from: {{ data.source }}</h3>
            <p>{{ data.description }}</p>
            <p style="font-size:12px; color:gray;">🔑 Authenticated via API Key</p>

            {% if data.status == 'PENDING' %}
                <a href="/approve/{{ id }}"><button style="background:green; color:white; padding:15px; border:none; cursor:pointer;">✅ APPROVE</button></a>
                <a href="/reject/{{ id }}"><button style="background:red; color:white; padding:15px; border:none; cursor:pointer;">❌ REJECT</button></a>
            {% else %}
                <p>Status: <b style="color:green">{{ data.status }}</b></p>
            {% endif %}
        </div>
    {% endfor %}
    """
    return render_template_string(html, db=transactions)


@app.route('/api/request', methods=['POST'])
def create_request():
    # SECURITY CHECK
    if not check_auth():
        return jsonify({"error": "Unauthorized. Please buy an API Key."}), 401

    data = request.json
    req_id = str(uuid.uuid4())[:8]
    transactions[req_id] = {
        "source": API_KEYS[request.headers.get('X-API-KEY')],  # Use the name associated with the key
        "description": data.get("description"),
        "status": "PENDING"
    }
    return jsonify({"id": req_id})


@app.route('/api/check/<req_id>')
def check_status(req_id):
    # Status checks don't strictly need auth, but let's be safe
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401

    if req_id in transactions:
        return jsonify({"status": transactions[req_id]["status"]})
    return jsonify({"status": "UNKNOWN"})


@app.route('/approve/<req_id>')
def approve(req_id):
    transactions[req_id]["status"] = "APPROVED"
    return "Authorized."


@app.route('/reject/<req_id>')
def reject(req_id):
    transactions[req_id]["status"] = "REJECTED"
    return "Rejected."


if __name__ == '__main__':
    app.run(port=5000, threaded=True)