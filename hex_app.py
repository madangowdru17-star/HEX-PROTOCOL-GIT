# app.py - Hex Cheats Admin Panel
import os
import json
import hashlib
import secrets
import string
import time
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template_string, redirect, session
from flask_cors import CORS
from functools import wraps

app = Flask(__name__)
app.secret_key = "HEX_CHEATS_SUPREME_SECRET_KEY_2026"
CORS(app)

# =============================================
# DATA STORAGE
# =============================================

DATA_FILE = "hex_data.json"
KEYS_FILE = "hex_keys.json"
USERS_FILE = "hex_users.json"
DEVICES_FILE = "hex_devices.json"

def load_data(filename, default):
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default

def save_data(filename, data):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

# =============================================
# LOAD ALL DATA
# =============================================

keys_data = load_data(KEYS_FILE, {"keys": [], "used_keys": []})
users_data = load_data(USERS_FILE, {"users": []})
devices_data = load_data(DEVICES_FILE, {"devices": []})
settings_data = load_data(DATA_FILE, {
    "total_keys": 0,
    "active_keys": 0,
    "total_users": 0,
    "total_devices": 0,
    "last_updated": "",
    "admin_password": "admin123",
    "key_price": 25.00,
    "currency": "USD"
})

# =============================================
# HELPER FUNCTIONS
# =============================================

def generate_key(length=24):
    chars = string.ascii_uppercase + string.digits
    return ''.join(secrets.choice(chars) for _ in range(length))

def generate_license_key():
    parts = []
    for i in range(4):
        parts.append(generate_key(6))
    return '-'.join(parts)

def get_device_fingerprint(request):
    user_agent = request.headers.get('User-Agent', 'Unknown')
    ip = request.remote_addr
    combined = f"{user_agent}|{ip}"
    return hashlib.sha256(combined.encode()).hexdigest()

def validate_key(key):
    for k in keys_data["keys"]:
        if k["key"] == key:
            if not k.get("used", False):
                return True, k
            return False, "Key already used"
    return False, "Invalid key"

def check_device_limit(device_id):
    device_count = sum(1 for d in devices_data["devices"] if d["device_id"] == device_id)
    return device_count < 3

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return jsonify({"error": "Admin access required"}), 401
        return f(*args, **kwargs)
    return decorated

# =============================================
# ADMIN AUTH
# =============================================

@app.route('/admin/login', methods=['POST'])
def admin_login():
    data = request.json
    password = data.get('password')
    if password == settings_data["admin_password"]:
        session['admin_logged_in'] = True
        return jsonify({"success": True, "message": "Login successful"})
    return jsonify({"error": "Invalid password"}), 401

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return jsonify({"success": True, "message": "Logged out"})

# =============================================
# KEY GENERATION API
# =============================================

@app.route('/api/generate', methods=['POST'])
@admin_required
def generate_keys():
    data = request.json
    count = data.get('count', 1)
    duration_days = data.get('duration', 30)
    key_type = data.get('type', 'premium')
    
    generated_keys = []
    for i in range(count):
        license_key = generate_license_key()
        expiry = (datetime.now() + timedelta(days=duration_days)).isoformat()
        
        key_data = {
            "key": license_key,
            "type": key_type,
            "duration": duration_days,
            "created_at": datetime.now().isoformat(),
            "expires_at": expiry,
            "used": False,
            "used_by": None,
            "device_id": None,
            "activated_at": None
        }
        keys_data["keys"].append(key_data)
        generated_keys.append(license_key)
    
    keys_data["total_keys"] = len(keys_data["keys"])
    save_data(KEYS_FILE, keys_data)
    
    return jsonify({
        "success": True,
        "keys": generated_keys,
        "count": count,
        "duration": duration_days
    })

# =============================================
# KEY ACTIVATION API
# =============================================

@app.route('/api/activate', methods=['POST'])
def activate_key():
    data = request.json
    key = data.get('key')
    username = data.get('username')
    device_id = data.get('device_id')
    
    if not key or not username:
        return jsonify({"error": "Key and username required"}), 400
    
    # Validate key
    valid, result = validate_key(key)
    if not valid:
        return jsonify({"error": result}), 400
    
    # Check device limit
    if device_id and not check_device_limit(device_id):
        return jsonify({"error": "Device limit exceeded (max 3 devices)"}), 400
    
    # Find and update key
    for k in keys_data["keys"]:
        if k["key"] == key:
            k["used"] = True
            k["used_by"] = username
            k["device_id"] = device_id
            k["activated_at"] = datetime.now().isoformat()
            break
    
    # Add user
    user_data = {
        "username": username,
        "key": key,
        "device_id": device_id,
        "activated_at": datetime.now().isoformat(),
        "expires_at": result["expires_at"]
    }
    users_data["users"].append(user_data)
    
    # Add device
    if device_id:
        device_data = {
            "device_id": device_id,
            "username": username,
            "key": key,
            "registered_at": datetime.now().isoformat()
        }
        devices_data["devices"].append(device_data)
    
    save_data(KEYS_FILE, keys_data)
    save_data(USERS_FILE, users_data)
    save_data(DEVICES_FILE, devices_data)
    
    return jsonify({
        "success": True,
        "message": "Key activated successfully",
        "username": username,
        "key": key,
        "expires_at": result["expires_at"]
    })

# =============================================
# KEY VERIFICATION API
# =============================================

@app.route('/api/verify', methods=['POST'])
def verify_key():
    data = request.json
    key = data.get('key')
    device_id = data.get('device_id')
    
    if not key:
        return jsonify({"error": "Key required"}), 400
    
    valid, result = validate_key(key)
    if not valid:
        return jsonify({"valid": False, "error": result}), 400
    
    # Check if key is expired
    expires_at = datetime.fromisoformat(result["expires_at"])
    if expires_at < datetime.now():
        return jsonify({
            "valid": False,
            "error": "Key has expired",
            "expires_at": result["expires_at"]
        }), 400
    
    # Check device
    if device_id:
        device_exists = any(d["device_id"] == device_id for d in devices_data["devices"])
        if not device_exists:
            return jsonify({
                "valid": False,
                "error": "Device not registered for this key"
            }), 400
    
    return jsonify({
        "valid": True,
        "key": key,
        "type": result["type"],
        "expires_at": result["expires_at"],
        "remaining_days": (expires_at - datetime.now()).days
    })

# =============================================
# ADMIN DASHBOARD API
# =============================================

@app.route('/api/admin/stats')
@admin_required
def admin_stats():
    total_keys = len(keys_data["keys"])
    used_keys = sum(1 for k in keys_data["keys"] if k.get("used", False))
    active_keys = total_keys - used_keys
    
    return jsonify({
        "total_keys": total_keys,
        "used_keys": used_keys,
        "active_keys": active_keys,
        "total_users": len(users_data["users"]),
        "total_devices": len(devices_data["devices"]),
        "admin_password": settings_data["admin_password"],
        "key_price": settings_data["key_price"],
        "currency": settings_data["currency"]
    })

@app.route('/api/admin/keys')
@admin_required
def admin_keys():
    return jsonify(keys_data["keys"])

@app.route('/api/admin/users')
@admin_required
def admin_users():
    return jsonify(users_data["users"])

@app.route('/api/admin/devices')
@admin_required
def admin_devices():
    return jsonify(devices_data["devices"])

@app.route('/api/admin/delete/key', methods=['POST'])
@admin_required
def delete_key():
    data = request.json
    key = data.get('key')
    
    keys_data["keys"] = [k for k in keys_data["keys"] if k["key"] != key]
    save_data(KEYS_FILE, keys_data)
    
    return jsonify({"success": True, "message": "Key deleted"})

@app.route('/api/admin/update/password', methods=['POST'])
@admin_required
def update_password():
    data = request.json
    new_password = data.get('password')
    
    if not new_password or len(new_password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    
    settings_data["admin_password"] = new_password
    save_data(DATA_FILE, settings_data)
    
    return jsonify({"success": True, "message": "Password updated"})

# =============================================
# UI - ADMIN PANEL
# =============================================

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HEX CHEATS - ADMIN PANEL</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0a0a0a;
            color: #ffffff;
            min-height: 100vh;
        }
        .header {
            background: linear-gradient(135deg, #00ff88, #00cc66);
            padding: 20px 40px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 4px 20px rgba(0, 255, 136, 0.3);
        }
        .header h1 {
            font-size: 28px;
            color: #0a0a0a;
            font-weight: 900;
            letter-spacing: 2px;
        }
        .header h1 i {
            margin-right: 10px;
        }
        .header .badge {
            background: #0a0a0a;
            color: #00ff88;
            padding: 8px 20px;
            border-radius: 20px;
            font-weight: 700;
            font-size: 14px;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 30px 20px;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: linear-gradient(145deg, #1a1a1a, #111111);
            border: 1px solid #2a2a2a;
            border-radius: 15px;
            padding: 25px;
            text-align: center;
            transition: all 0.3s ease;
        }
        .stat-card:hover {
            transform: translateY(-5px);
            border-color: #00ff88;
            box-shadow: 0 8px 30px rgba(0, 255, 136, 0.15);
        }
        .stat-card .number {
            font-size: 42px;
            font-weight: 900;
            color: #00ff88;
            margin: 10px 0;
        }
        .stat-card .label {
            font-size: 14px;
            color: #888;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .stat-card .icon {
            font-size: 30px;
            color: #00ff88;
        }
        .panel {
            background: #111111;
            border: 1px solid #2a2a2a;
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 25px;
        }
        .panel-title {
            font-size: 20px;
            font-weight: 700;
            margin-bottom: 20px;
            color: #00ff88;
        }
        .panel-title i {
            margin-right: 10px;
        }
        .input-group {
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            align-items: center;
        }
        .input-group input, .input-group select {
            flex: 1;
            min-width: 150px;
            padding: 12px 18px;
            background: #1a1a1a;
            border: 2px solid #2a2a2a;
            border-radius: 10px;
            color: #ffffff;
            font-size: 14px;
            transition: border-color 0.3s;
        }
        .input-group input:focus, .input-group select:focus {
            outline: none;
            border-color: #00ff88;
        }
        .btn {
            padding: 12px 30px;
            border: none;
            border-radius: 10px;
            font-weight: 700;
            font-size: 14px;
            cursor: pointer;
            transition: all 0.3s ease;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .btn-primary {
            background: linear-gradient(135deg, #00ff88, #00cc66);
            color: #0a0a0a;
        }
        .btn-primary:hover {
            transform: scale(1.05);
            box-shadow: 0 4px 20px rgba(0, 255, 136, 0.4);
        }
        .btn-danger {
            background: linear-gradient(135deg, #ff4444, #cc0000);
            color: #ffffff;
        }
        .btn-danger:hover {
            transform: scale(1.05);
            box-shadow: 0 4px 20px rgba(255, 68, 68, 0.4);
        }
        .btn-outline {
            background: transparent;
            border: 2px solid #2a2a2a;
            color: #ffffff;
        }
        .btn-outline:hover {
            border-color: #00ff88;
            color: #00ff88;
        }
        .key-display {
            background: #0a0a0a;
            border: 2px solid #2a2a2a;
            border-radius: 10px;
            padding: 15px 20px;
            font-family: 'Courier New', monospace;
            font-size: 18px;
            color: #00ff88;
            word-break: break-all;
            margin: 15px 0;
        }
        .table-container {
            overflow-x: auto;
            margin-top: 15px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        table th {
            background: #1a1a1a;
            padding: 12px 15px;
            text-align: left;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: #888;
            border-bottom: 2px solid #2a2a2a;
        }
        table td {
            padding: 12px 15px;
            border-bottom: 1px solid #1a1a1a;
            font-size: 13px;
        }
        table tr:hover {
            background: #0d0d0d;
        }
        .status-active {
            color: #00ff88;
        }
        .status-used {
            color: #ffaa00;
        }
        .status-expired {
            color: #ff4444;
        }
        .login-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.95);
            display: flex;
            justify-content: center;
            align-items: center;
            z-index: 9999;
        }
        .login-box {
            background: #111111;
            border: 2px solid #2a2a2a;
            border-radius: 20px;
            padding: 50px;
            max-width: 420px;
            width: 90%;
            text-align: center;
        }
        .login-box h2 {
            color: #00ff88;
            font-size: 32px;
            margin-bottom: 10px;
        }
        .login-box p {
            color: #888;
            margin-bottom: 30px;
        }
        .login-box input {
            width: 100%;
            padding: 15px;
            background: #1a1a1a;
            border: 2px solid #2a2a2a;
            border-radius: 10px;
            color: #ffffff;
            font-size: 16px;
            margin-bottom: 20px;
        }
        .login-box input:focus {
            outline: none;
            border-color: #00ff88;
        }
        .login-box .btn {
            width: 100%;
        }
        .tab-buttons {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        .tab-btn {
            padding: 10px 25px;
            background: #1a1a1a;
            border: 2px solid #2a2a2a;
            border-radius: 10px;
            color: #888;
            cursor: pointer;
            transition: all 0.3s;
            font-weight: 600;
        }
        .tab-btn.active {
            border-color: #00ff88;
            color: #00ff88;
            background: #0a0a0a;
        }
        .tab-btn:hover {
            border-color: #00ff88;
        }
        .generated-keys {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin: 15px 0;
        }
        .generated-key-item {
            background: #0a0a0a;
            border: 1px solid #2a2a2a;
            border-radius: 8px;
            padding: 10px 15px;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            color: #00ff88;
        }
        .toast {
            position: fixed;
            bottom: 30px;
            right: 30px;
            padding: 15px 25px;
            border-radius: 10px;
            font-weight: 600;
            z-index: 10000;
            animation: slideIn 0.5s ease;
        }
        .toast-success {
            background: #00cc66;
            color: #0a0a0a;
        }
        .toast-error {
            background: #ff4444;
            color: #ffffff;
        }
        @keyframes slideIn {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        .copy-btn {
            background: none;
            border: none;
            color: #00ff88;
            cursor: pointer;
            margin-left: 10px;
            font-size: 16px;
        }
        .copy-btn:hover {
            color: #ffffff;
        }
        .footer {
            text-align: center;
            padding: 30px;
            color: #444;
            font-size: 13px;
            border-top: 1px solid #1a1a1a;
            margin-top: 30px;
        }
        .footer a {
            color: #00ff88;
            text-decoration: none;
        }
        @media (max-width: 768px) {
            .header {
                flex-direction: column;
                gap: 10px;
                padding: 15px;
            }
            .header h1 {
                font-size: 20px;
            }
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            .stat-card .number {
                font-size: 28px;
            }
            .input-group {
                flex-direction: column;
            }
            .input-group input, .input-group select {
                width: 100%;
            }
            .login-box {
                padding: 30px 20px;
            }
        }
        .scrollable {
            max-height: 400px;
            overflow-y: auto;
        }
        .scrollable::-webkit-scrollbar {
            width: 6px;
        }
        .scrollable::-webkit-scrollbar-track {
            background: #0a0a0a;
        }
        .scrollable::-webkit-scrollbar-thumb {
            background: #2a2a2a;
            border-radius: 3px;
        }
        .scrollable::-webkit-scrollbar-thumb:hover {
            background: #00ff88;
        }
    </style>
</head>
<body>

    <div id="loginOverlay" class="login-overlay">
        <div class="login-box">
            <h2><i class="fas fa-shield-halved"></i> HEX CHEATS</h2>
            <p>Admin Panel Access</p>
            <input type="password" id="adminPass" placeholder="Enter Admin Password" onkeypress="if(event.key==='Enter') adminLogin()">
            <button class="btn btn-primary" onclick="adminLogin()">Unlock Panel</button>
            <p style="margin-top: 15px; font-size: 12px; color: #555;">Default: admin123</p>
        </div>
    </div>

    <div class="header">
        <h1><i class="fas fa-shield-halved"></i> HEX CHEATS ADMIN</h1>
        <span class="badge"><i class="fas fa-crown"></i> PREMIUM SYSTEM</span>
    </div>

    <div class="container" id="mainContent" style="display:none;">

        <div class="stats-grid" id="statsGrid">
            <div class="stat-card">
                <div class="icon"><i class="fas fa-keys"></i></div>
                <div class="number" id="totalKeys">0</div>
                <div class="label">Total Keys</div>
            </div>
            <div class="stat-card">
                <div class="icon"><i class="fas fa-check-circle"></i></div>
                <div class="number" id="activeKeys">0</div>
                <div class="label">Active Keys</div>
            </div>
            <div class="stat-card">
                <div class="icon"><i class="fas fa-users"></i></div>
                <div class="number" id="totalUsers">0</div>
                <div class="label">Total Users</div>
            </div>
            <div class="stat-card">
                <div class="icon"><i class="fas fa-laptop"></i></div>
                <div class="number" id="totalDevices">0</div>
                <div class="label">Registered Devices</div>
            </div>
        </div>

        <div class="panel">
            <div class="panel-title"><i class="fas fa-plus-circle"></i> Generate Keys</div>
            <div class="input-group">
                <input type="number" id="keyCount" value="1" min="1" max="100">
                <input type="number" id="keyDuration" value="30" min="1" max="365">
                <select id="keyType">
                    <option value="premium">Premium</option>
                    <option value="vip">VIP</option>
                    <option value="standard">Standard</option>
                    <option value="trial">Trial</option>
                </select>
                <button class="btn btn-primary" onclick="generateKeys()"><i class="fas fa-wand-magic-sparkles"></i> Generate</button>
            </div>
            <div id="generatedKeysContainer"></div>
        </div>

        <div class="panel">
            <div class="tab-buttons">
                <button class="tab-btn active" onclick="switchTab('keys')"><i class="fas fa-keys"></i> Keys</button>
                <button class="tab-btn" onclick="switchTab('users')"><i class="fas fa-users"></i> Users</button>
                <button class="tab-btn" onclick="switchTab('devices')"><i class="fas fa-laptop"></i> Devices</button>
                <button class="tab-btn" onclick="switchTab('settings')"><i class="fas fa-gear"></i> Settings</button>
            </div>

            <div id="tabKeys" class="tab-content">
                <div class="table-container scrollable">
                    <table>
                        <thead>
                            <tr>
                                <th>Key</th>
                                <th>Type</th>
                                <th>Duration</th>
                                <th>Status</th>
                                <th>Used By</th>
                                <th>Expires</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody id="keysTableBody"></tbody>
                    </table>
                </div>
            </div>

            <div id="tabUsers" class="tab-content" style="display:none;">
                <div class="table-container scrollable">
                    <table>
                        <thead>
                            <tr>
                                <th>Username</th>
                                <th>Key</th>
                                <th>Device ID</th>
                                <th>Activated</th>
                                <th>Expires</th>
                            </tr>
                        </thead>
                        <tbody id="usersTableBody"></tbody>
                    </table>
                </div>
            </div>

            <div id="tabDevices" class="tab-content" style="display:none;">
                <div class="table-container scrollable">
                    <table>
                        <thead>
                            <tr>
                                <th>Device ID</th>
                                <th>Username</th>
                                <th>Key</th>
                                <th>Registered</th>
                            </tr>
                        </thead>
                        <tbody id="devicesTableBody"></tbody>
                    </table>
                </div>
            </div>

            <div id="tabSettings" class="tab-content" style="display:none;">
                <div style="display:grid; gap:20px; max-width:500px;">
                    <div>
                        <label style="color:#888; display:block; margin-bottom:5px;">Admin Password</label>
                        <div class="input-group">
                            <input type="password" id="newPassword" placeholder="New password (min 6 chars)">
                            <button class="btn btn-primary" onclick="updatePassword()">Update</button>
                        </div>
                    </div>
                    <div>
                        <label style="color:#888; display:block; margin-bottom:5px;">Key Price</label>
                        <div class="input-group">
                            <input type="number" id="keyPrice" step="0.01" placeholder="Price">
                            <select id="currencySelect">
                                <option value="USD">USD</option>
                                <option value="EUR">EUR</option>
                                <option value="GBP">GBP</option>
                                <option value="BDT">BDT</option>
                                <option value="INR">INR</option>
                            </select>
                            <button class="btn btn-primary" onclick="updateSettings()">Save</button>
                        </div>
                    </div>
                    <div>
                        <button class="btn btn-danger" onclick="clearAllData()"><i class="fas fa-trash"></i> Clear All Data</button>
                    </div>
                </div>
            </div>
        </div>

        <div class="footer">
            <i class="fas fa-shield-halved" style="color:#00ff88;"></i> HEX CHEATS PREMIUM SYSTEM &bull; <span id="currentTime"></span> &bull; <a href="#" onclick="adminLogout()">Logout</a>
        </div>
    </div>

    <script>
        let isLoggedIn = false;
        let allKeys = [];
        let allUsers = [];
        let allDevices = [];

        function adminLogin() {
            const pass = document.getElementById('adminPass').value;
            fetch('/admin/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password: pass })
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    isLoggedIn = true;
                    document.getElementById('loginOverlay').style.display = 'none';
                    document.getElementById('mainContent').style.display = 'block';
                    loadAllData();
                    showToast('Login successful', 'success');
                } else {
                    showToast('Invalid password', 'error');
                }
            })
            .catch(() => showToast('Login failed', 'error'));
        }

        function adminLogout() {
            fetch('/admin/logout')
            .then(() => {
                isLoggedIn = false;
                document.getElementById('loginOverlay').style.display = 'flex';
                document.getElementById('mainContent').style.display = 'none';
                showToast('Logged out', 'success');
            });
        }

        function loadAllData() {
            loadStats();
            loadKeys();
            loadUsers();
            loadDevices();
            updateClock();
            setInterval(updateClock, 1000);
        }

        function loadStats() {
            fetch('/api/admin/stats')
            .then(res => res.json())
            .then(data => {
                document.getElementById('totalKeys').textContent = data.total_keys || 0;
                document.getElementById('activeKeys').textContent = data.active_keys || 0;
                document.getElementById('totalUsers').textContent = data.total_users || 0;
                document.getElementById('totalDevices').textContent = data.total_devices || 0;
                if (data.key_price) {
                    document.getElementById('keyPrice').value = data.key_price;
                    document.getElementById('currencySelect').value = data.currency || 'USD';
                }
            });
        }

        function loadKeys() {
            fetch('/api/admin/keys')
            .then(res => res.json())
            .then(data => {
                allKeys = data;
                const tbody = document.getElementById('keysTableBody');
                tbody.innerHTML = '';
                data.forEach(k => {
                    const used = k.used || false;
                    const status = used ? 'USED' : 'ACTIVE';
                    const statusClass = used ? 'status-used' : 'status-active';
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td style="font-family:monospace; font-size:12px;">${k.key}</td>
                        <td><span class="status-active">${k.type}</span></td>
                        <td>${k.duration} days</td>
                        <td class="${statusClass}">${status}</td>
                        <td>${k.used_by || '-'}</td>
                        <td style="font-size:11px;">${new Date(k.expires_at).toLocaleDateString()}</td>
                        <td>
                            <button class="btn btn-danger" style="padding:5px 12px; font-size:11px;" onclick="deleteKey('${k.key}')">
                                <i class="fas fa-trash"></i>
                            </button>
                        </td>
                    `;
                    tbody.appendChild(tr);
                });
            });
        }

        function loadUsers() {
            fetch('/api/admin/users')
            .then(res => res.json())
            .then(data => {
                allUsers = data;
                const tbody = document.getElementById('usersTableBody');
                tbody.innerHTML = '';
                data.forEach(u => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td><strong>${u.username}</strong></td>
                        <td style="font-family:monospace; font-size:11px;">${u.key}</td>
                        <td style="font-family:monospace; font-size:11px;">${u.device_id || '-'}</td>
                        <td style="font-size:11px;">${new Date(u.activated_at).toLocaleString()}</td>
                        <td style="font-size:11px;">${new Date(u.expires_at).toLocaleDateString()}</td>
                    `;
                    tbody.appendChild(tr);
                });
            });
        }

        function loadDevices() {
            fetch('/api/admin/devices')
            .then(res => res.json())
            .then(data => {
                allDevices = data;
                const tbody = document.getElementById('devicesTableBody');
                tbody.innerHTML = '';
                data.forEach(d => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td style="font-family:monospace; font-size:11px;">${d.device_id}</td>
                        <td><strong>${d.username}</strong></td>
                        <td style="font-family:monospace; font-size:11px;">${d.key}</td>
                        <td style="font-size:11px;">${new Date(d.registered_at).toLocaleString()}</td>
                    `;
                    tbody.appendChild(tr);
                });
            });
        }

        function generateKeys() {
            const count = document.getElementById('keyCount').value;
            const duration = document.getElementById('keyDuration').value;
            const type = document.getElementById('keyType').value;

            fetch('/api/generate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ count: parseInt(count), duration: parseInt(duration), type: type })
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    const container = document.getElementById('generatedKeysContainer');
                    let html = '<div class="generated-keys">';
                    data.keys.forEach(k => {
                        html += `<div class="generated-key-item">${k} <button class="copy-btn" onclick="copyKey('${k}')"><i class="fas fa-copy"></i></button></div>`;
                    });
                    html += '</div>';
                    container.innerHTML = html;
                    showToast(`Generated ${data.count} keys`, 'success');
                    loadAllData();
                } else {
                    showToast('Generation failed', 'error');
                }
            })
            .catch(() => showToast('Generation error', 'error'));
        }

        function deleteKey(key) {
            if (!confirm('Delete this key?')) return;
            fetch('/api/admin/delete/key', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ key: key })
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    showToast('Key deleted', 'success');
                    loadAllData();
                }
            });
        }

        function updatePassword() {
            const pass = document.getElementById('newPassword').value;
            if (pass.length < 6) {
                showToast('Password must be at least 6 characters', 'error');
                return;
            }
            fetch('/api/admin/update/password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password: pass })
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    showToast('Password updated', 'success');
                    document.getElementById('newPassword').value = '';
                }
            });
        }

        function updateSettings() {
            showToast('Settings saved', 'success');
        }

        function clearAllData() {
            if (!confirm('Clear all data? This cannot be undone!')) return;
            showToast('Feature: Clear all data', 'error');
        }

        function copyKey(key) {
            navigator.clipboard.writeText(key);
            showToast('Key copied to clipboard', 'success');
        }

        function switchTab(tab) {
            document.querySelectorAll('.tab-content').forEach(el => el.style.display = 'none');
            document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
            
            document.getElementById('tabKeys').style.display = tab === 'keys' ? 'block' : 'none';
            document.getElementById('tabUsers').style.display = tab === 'users' ? 'block' : 'none';
            document.getElementById('tabDevices').style.display = tab === 'devices' ? 'block' : 'none';
            document.getElementById('tabSettings').style.display = tab === 'settings' ? 'block' : 'none';
            
            document.querySelectorAll('.tab-btn').forEach(el => {
                if (el.textContent.toLowerCase().includes(tab)) el.classList.add('active');
            });
        }

        function showToast(message, type) {
            const existing = document.querySelector('.toast');
            if (existing) existing.remove();
            
            const toast = document.createElement('div');
            toast.className = `toast toast-${type}`;
            toast.innerHTML = message;
            document.body.appendChild(toast);
            
            setTimeout(() => toast.remove(), 3000);
        }

        function updateClock() {
            document.getElementById('currentTime').textContent = new Date().toLocaleString();
        }

        // Check if already logged in
        document.addEventListener('DOMContentLoaded', function() {
            // Show login by default
        });
    </script>
</body>
</html>
'''

@app.route('/')
def admin_panel():
    return render_template_string(HTML_TEMPLATE)

# =============================================
# RUN THE APP
# =============================================

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5005, debug=True)
