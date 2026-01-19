import os
import uuid
import json
import psycopg2
import requests
import secrets
from flask import Flask, request, jsonify, render_template_string, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from openai import OpenAI

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'default_secret_key')

# --- CONFIGURATION ---
DB_URL = os.environ.get('DATABASE_URL')
OPENAI_KEY = os.environ.get('OPENAI_API_KEY')

client = None
if OPENAI_KEY:
    client = OpenAI(api_key=OPENAI_KEY)


# --- 🧠 VIGIL BRAIN: DATA LEAK DETECTION ---
def analyze_security_risk(prompt_text):
    # Internal Python function - NO API CALLS needed to use this
    if not client: return 0, "AI Not Configured"
    try:
        system_prompt = """
        You are VIGIL, a corporate Data Loss Prevention (DLP) engine. 
        Analyze the input for SENSITIVE DATA leaks.

        Flag High Risk (80-100) for:
        - API Keys (sk-..., AWS, Azure tokens)
        - Database Credentials & Connection Strings
        - PII (SSN, Emails, Phone Numbers, Addresses)
        - Internal proprietary code markings or confidential tags

        Return JSON: {"risk_score": 0-100, "risk_reason": "short explanation"}
        """
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Scan: {prompt_text}"}
            ],
            response_format={"type": "json_object"}
        )
        result = json.loads(response.choices[0].message.content)
        return result.get('risk_score', 0), result.get('risk_reason', "Safe")
    except Exception as e:
        print(f"❌ AI Error: {e}")
        return 50, "Scan Error"


# --- DATABASE SETUP (V5 - Keeping existing data) ---
def get_db_connection():
    if not DB_URL: raise ValueError("DATABASE_URL is missing")
    conn = psycopg2.connect(DB_URL)
    return conn


def init_db():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
                    CREATE TABLE IF NOT EXISTS users_v5
                    (
                        id
                        SERIAL
                        PRIMARY
                        KEY,
                        username
                        VARCHAR
                    (
                        50
                    ) UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        discord_webhook TEXT,
                        api_key VARCHAR
                    (
                        64
                    ) UNIQUE
                        );
                    """)
        cur.execute("""
                    CREATE TABLE IF NOT EXISTS transactions_v5
                    (
                        id
                        VARCHAR
                    (
                        10
                    ) PRIMARY KEY,
                        user_id INTEGER REFERENCES users_v5
                    (
                        id
                    ),
                        source VARCHAR
                    (
                        100
                    ),
                        description TEXT,
                        status VARCHAR
                    (
                        20
                    ),
                        risk_score INTEGER,
                        risk_reason TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        );
                    """)
        conn.commit();
        cur.close();
        conn.close()
    except Exception as e:
        print(f"❌ DB Init Error: {e}")


if DB_URL: init_db()

# --- AUTH SETUP ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'landing'


class User(UserMixin):
    def __init__(self, id, username, password_hash, discord_webhook, api_key):
        self.id = id;
        self.username = username;
        self.password_hash = password_hash;
        self.discord_webhook = discord_webhook;
        self.api_key = api_key


@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection();
    cur = conn.cursor()
    cur.execute("SELECT * FROM users_v5 WHERE id = %s", (user_id,))
    res = cur.fetchone();
    cur.close();
    conn.close()
    if res: return User(id=res[0], username=res[1], password_hash=res[2], discord_webhook=res[3], api_key=res[4])
    return None


def send_discord_alert(webhook_url, message, color=None):
    if not webhook_url: return
    try:
        requests.post(webhook_url, json={"embeds": [{"description": message, "color": color}]}, timeout=5)
    except:
        pass


# ===========================
# === PROFESSIONAL DESIGN ===
# ===========================

# Shared Head Section for consistent styling
BASE_HEAD = """
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VIGIL | The AI Firewall</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>