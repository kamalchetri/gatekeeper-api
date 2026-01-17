from flask import Flask, request, jsonify, render_template_string
import uuid

app = Flask(__name__)

# DATABASE
transactions = {}


@app.route('/')
def dashboard():
    # Auto-refresh every 2 seconds
    html = """
    <meta http-equiv="refresh" content="2">
    <style>body{font-family:sans-serif; padding:2rem; text-align:center; background:#f4f4f9;}</style>
    <h1>🛡️ Gatekeeper HQ</h1>
    <p><i>Server Status: ONLINE</i></p>

    {% for id, data in db.items() %}
        <div style="background:white; padding:20px; margin:20px auto; max-width:500px; border-radius:10px; border: 1px solid #ddd;">
            <h3>⚠️ Request: {{ data.source }}</h3>
            <p>{{ data.description }}</p>

            {% if data.status == 'PENDING' %}
                <p>Status: <b style="color:orange">WAITING</b></p>
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
    data = request.json
    req_id = str(uuid.uuid4())[:8]
    transactions[req_id] = {
        "source": data.get("source"),
        "description": data.get("description"),
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
    transactions[req_id]["status"] = "APPROVED"
    return "Authorized."


@app.route('/reject/<req_id>')
def reject(req_id):
    transactions[req_id]["status"] = "REJECTED"
    return "Rejected."


if __name__ == '__main__':
    # THREADED=TRUE means it can handle multiple requests without blocking
    print(">>> SERVER STARTING... I WILL RUN FOREVER. <<<")
    app.run(port=5000, threaded=True)