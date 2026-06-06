from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import requests
import time 

# --- INITIALIZATION ---
base_dir = os.path.abspath(os.path.dirname(__file__))
# Deployment Fix: Look in root for templates/static since all files are in one folder
app = Flask(__name__, template_folder='.', static_folder='.') 
app.secret_key = "ll_terminal_production_key_2025"

# --- DATABASE CONFIG (Cloud Optimized) ---
# Using absolute path to ensure SQLite works on Render/Linux environments
db_path = os.path.join(base_dir, 'saas_platform.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    store_domain = db.Column(db.String(200), nullable=True)
    shopify_api_key = db.Column(db.String(200), nullable=True)
    webhook_url = db.Column(db.String(200), nullable=True)

with app.app_context():
    db.create_all()

# --- HELPER: Deployment File Finder ---
def find_template(name):
    """Ensures index.html, Index.html, and INDEX.HTML all work on Linux servers."""
    try:
        files = os.listdir(base_dir)
        for f in files:
            if f.lower() == name.lower():
                return f
    except: pass
    return name

# --- CORE PAGE ROUTES ---

@app.route('/')
def home():
    return render_template(find_template('index.html'))

@app.route('/auth')
def auth_page():
    return render_template(find_template('auth.html'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session: return redirect(url_for('auth_page'))
    user = User.query.get(session['user_id'])
    is_connected = bool(user.shopify_api_key)
    return render_template(find_template('dashboard.html'), 
                           username=user.username, 
                           user=user, 
                           shopify_connected=is_connected)

@app.route('/settings')
def settings():
    if 'user_id' not in session: return redirect(url_for('auth_page'))
    user = User.query.get(session['user_id'])
    return render_template(find_template('settings.html'), user=user, email=user.email)

# --- API: WEB SCAN DIAGNOSTIC ENGINE ---

@app.route('/api/perform_scan', methods=['POST'])
def perform_scan():
    if 'user_id' not in session: return jsonify({"success": False, "message": "Unauthorized"}), 401
    data = request.get_json()
    domain = data.get('domain', '').lower().replace('https://', '').replace('http://', '').strip('/')
    
    if not domain: return jsonify({"success": False, "message": "Invalid Domain Node"}), 400

    try:
        start_time = time.time()
        headers = {'User-Agent': 'L&L Terminal Cloud Diagnostic/1.0'}
        # Perform live HTTP handshake
        response = requests.get(f"https://{domain}", headers=headers, timeout=20)
        velocity_ms = int((time.time() - start_time) * 1000)
        
        # Architecture Fingerprinting
        body = response.text.lower()
        h = response.headers
        platform = "OTHER"
        if "shopify" in body or "x-shopify" in str(h).lower(): platform = "SHOPIFY"
        elif "wix.com" in body: platform = "WIX"
        elif "wp-content" in body: platform = "WORDPRESS"

        # Security Audit
        security = "STANDARD"
        if "Strict-Transport-Security" in h: security = "SECURED"
        if "Content-Security-Policy" in h: security = "HARDENED"
        
        return jsonify({
            "success": True,
            "platform": platform,
            "security": security,
            "velocity": f"{velocity_ms}ms",
            "health": f"{max(5, 100 - (velocity_ms // 120))}/100",
            "logs": [
                f"Establishing bridge to {domain}...",
                f"Handshake successful: {velocity_ms}ms latency.",
                f"Node architecture identified as {platform}.",
                f"Security scan complete: {security} layer detected."
            ]
        })
    except Exception as e:
        return jsonify({"success": False, "message": f"Connection Refused: {str(e)}"}), 400

# --- API: DASHBOARD STATS ---

@app.route('/api/stats')
def get_stats():
    if 'user_id' not in session: return jsonify({"connected": False}), 401
    user = User.query.get(session['user_id'])
    if not user or not user.shopify_api_key: return jsonify({"connected": False})

    headers = {"X-Shopify-Access-Token": user.shopify_api_key}
    try:
        # 25s timeout for stable handshake on mobile networks
        res = requests.get(f"https://{user.store_domain}/admin/api/2024-04/shop.json", headers=headers, timeout=25)
        if res.status_code == 200:
            shop = res.json()['shop']
            return jsonify({
                "connected": True, "shop_name": shop['name'], "currency": shop['currency'],
                "webhook_active": bool(user.webhook_url), "domain": user.store_domain,
                "chart_data": [10, 22, 15, 30, 28, 45]
            })
    except: pass
    return jsonify({"connected": False})

# --- API: INTEGRATION HANDSHAKE ---

@app.route('/verify_integrations', methods=['POST'])
def verify_integrations():
    if 'user_id' not in session: return jsonify({"message": "Unauthorized"}), 401
    user = User.query.get(session['user_id'])
    data = request.get_json()
    domain = data.get('store_domain').replace("https://", "").strip("/")
    
    headers = {"X-Shopify-Access-Token": data.get('shopify_api')}
    try:
        res = requests.get(f"https://{domain}/admin/api/2024-04/shop.json", headers=headers, timeout=25)
        if res.status_code == 200:
            user.store_domain = domain
            user.shopify_api_key = data.get('shopify_api')
            user.webhook_url = data.get('webhook_url')
            db.session.commit()
            return jsonify({"message": "Handshake Complete: Connection Locked"}), 200
        return jsonify({"message": "Handshake Rejected: Invalid Access Key"}), 400
    except:
        return jsonify({"message": "Connection Timeout: System offline"}), 500

# --- AUTH LOGIC ---

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if User.query.filter_by(email=data['email']).first():
        return jsonify({"message": "Email already registered"}), 400
    hashed = generate_password_hash(data['password'])
    new_user = User(username=data['username'], email=data['email'], password=hashed)
    db.session.add(new_user)
    db.session.commit()
    session['user_id'] = new_user.id
    return jsonify({"message": "Success"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data.get('email')).first()
    if user and check_password_hash(user.password, data.get('password')):
        session['user_id'] = user.id
        return jsonify({"message": "Success"}), 200
    return jsonify({"message": "Invalid Credentials"}), 401

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

# --- CATCH-ALL ROUTE ---

@app.route('/<path:page_name>')
def serve_any_page(page_name):
    # Standardize name (remove .html if exists)
    clean_name = page_name.replace('.html', '')
    target_file = find_template(clean_name + '.html')

    if os.path.exists(os.path.join(base_dir, target_file)):
        user = User.query.get(session['user_id']) if 'user_id' in session else None
        return render_template(target_file, user=user, email=user.email if user else None)
    
    return "<h1>404: System Node Not Found</h1>", 404

if __name__ == '__main__':
    # Render uses the PORT environment variable
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)