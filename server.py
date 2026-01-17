from flask import Flask, request, jsonify, render_template_string
import uuid

app = Flask(__name__)

# 1. API KEYS
API_KEYS = {
    "sk_live_12345": "Bank of America Bot",
}

transactions = {}


def check_auth():
    key = request.headers.get('X-API-KEY')
    return key in API_KEYS


@app.route('/')
def dashboard():
    html = """
    <meta http-equiv="refresh" content="5">
    <style>body{font-family:sans-serif; padding:2rem; text-align:center; background:#f4f4f9;}</style>
    <h1>🛡️ Gatekeeper HQ</h1>
    <p>Status: 🟢 SYSTEM STABLE</p>

    {% for id, data in db.items() %}
        <div style="background:white; padding:20px; margin:20px auto; max-width:500px; border-radius:10px; border: 1px solid #ddd;">
            <h3>⚠️ Request from: {{ data.source }}</h3>
            <p>{{ data.description }}</p>

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
    # This checks if the ID is valid instead of crashing
    if req_id not in transactions:
        return "<h1>❌ Error: Transaction ID not found.</h1><p>Please run the Client Bot again.</p>"

    transactions[req_id]["status"] = "APPROVED"
    return "<h1>Authorized.</h1><script>setTimeout(()=>window.location.href='/', 1000)</script>"


@app.route('/reject/<req_id>')
def reject(req_id):
    if req_id not in transactions:
        return "<h1>❌ Error: Transaction ID not found.</h1>"

    transactions[req_id]["status"] = "REJECTED"
    return "<h1>Rejected.</h1><script>setTimeout(()=>window.location.href='/', 1000)</script>"


if __name__ == '__main__':
    app.run(port=5000)