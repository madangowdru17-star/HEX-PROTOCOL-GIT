# app.py
import os
import json
import hashlib
import secrets
import string
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template_string, session
from flask_cors import CORS
from functools import wraps

app = Flask(__name__)
app.secret_key = "HEX_KEYS_SECRET_2026"
CORS(app)

# =============================================
# DATA FILES
# =============================================

KEYS_FILE = "keys.json"
USERS_FILE = "users.json"
DEVICES_FILE = "devices.json"

def load_data(filename):
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def save_data(filename, data):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

# =============================================
# HELPERS
# =============================================

def generate_key():
    chars = string.ascii_uppercase + string.digits
    return ''.join(secrets.choice(chars) for _ in range(16))

def get_device_id(request):
    user_agent = request.headers.get('User-Agent', 'unknown')
    ip = request.remote_addr
    combined = f"{user_agent}|{ip}"
    return hashlib.sha256(combined.encode()).hexdigest()[:32]

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('admin'):
            return jsonify({"error": "Admin access required"}), 401
        return f(*args, **kwargs)
    return decorated

# =============================================
# API ENDPOINTS
# =============================================

@app.route('/api/generate', methods=['POST'])
@admin_required
def generate_keys():
    try:
        data = request.json
        count = int(data.get('count', 1))
        duration_type = data.get('duration_type', 'hours')
        duration_value = int(data.get('duration_value', 24))
        
        keys = load_data(KEYS_FILE)
        generated = []
        
        for i in range(count):
            key = generate_key()
            
            if duration_type == 'days':
                expires = (datetime.now() + timedelta(days=duration_value)).isoformat()
            else:
                expires = (datetime.now() + timedelta(hours=duration_value)).isoformat()
            
            key_data = {
                "key": key,
                "duration_type": duration_type,
                "duration_value": duration_value,
                "created": datetime.now().isoformat(),
                "expires": expires,
                "used": False,
                "used_by": None,
                "device": None,
                "activated": None
            }
            keys.append(key_data)
            generated.append(key)
        
        save_data(KEYS_FILE, keys)
        
        return jsonify({
            "success": True,
            "keys": generated,
            "count": count,
            "duration_type": duration_type,
            "duration_value": duration_value,
            "message": f"Generated {count} key(s)"
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@app.route('/api/activate', methods=['POST'])
def activate_key():
    try:
        data = request.json
        key = data.get('key')
        username = data.get('username', 'user')
        device = data.get('device') or get_device_id(request)
        
        if not key:
            return jsonify({"error": "Key required"}), 400
        
        keys = load_data(KEYS_FILE)
        users = load_data(USERS_FILE)
        devices = load_data(DEVICES_FILE)
        
        for k in keys:
            if k['key'] == key:
                if k['used']:
                    return jsonify({"error": "Key already used"}), 400
                
                expires = datetime.fromisoformat(k['expires'])
                if expires < datetime.now():
                    return jsonify({"error": "Key expired"}), 400
                
                k['used'] = True
                k['used_by'] = username
                k['device'] = device
                k['activated'] = datetime.now().isoformat()
                
                user_data = {
                    "username": username,
                    "key": key,
                    "device": device,
                    "activated": datetime.now().isoformat(),
                    "expires": k['expires']
                }
                users.append(user_data)
                
                device_data = {
                    "device_id": device,
                    "username": username,
                    "key": key,
                    "registered": datetime.now().isoformat()
                }
                devices.append(device_data)
                
                save_data(KEYS_FILE, keys)
                save_data(USERS_FILE, users)
                save_data(DEVICES_FILE, devices)
                
                return jsonify({
                    "success": True,
                    "message": "Key activated",
                    "key": key,
                    "username": username,
                    "device": device,
                    "expires": k['expires']
                })
        
        return jsonify({"error": "Invalid key"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/verify', methods=['POST'])
def verify_key():
    try:
        data = request.json
        key = data.get('key')
        device = data.get('device') or get_device_id(request)
        
        if not key:
            return jsonify({"error": "Key required"}), 400
        
        keys = load_data(KEYS_FILE)
        
        for k in keys:
            if k['key'] == key:
                if not k['used']:
                    return jsonify({"valid": False, "error": "Key not activated"}), 400
                
                if k['device'] != device:
                    return jsonify({"valid": False, "error": "Device mismatch"}), 400
                
                expires = datetime.fromisoformat(k['expires'])
                if expires < datetime.now():
                    return jsonify({"valid": False, "error": "Key expired"}), 400
                
                return jsonify({
                    "valid": True,
                    "key": key,
                    "username": k['used_by'],
                    "device": k['device'],
                    "expires": k['expires']
                })
        
        return jsonify({"valid": False, "error": "Invalid key"}), 400
    except Exception as e:
        return jsonify({"valid": False, "error": str(e)}), 400

@app.route('/api/check', methods=['GET'])
def check_key():
    key = request.args.get('key')
    device = request.args.get('device')
    if not key:
        return jsonify({"error": "Key required"}), 400
    return verify_key()

@app.route('/api/stats', methods=['GET'])
def get_stats():
    try:
        keys = load_data(KEYS_FILE)
        users = load_data(USERS_FILE)
        
        total = len(keys)
        used = sum(1 for k in keys if k.get('used', False))
        active = total - used
        
        return jsonify({
            "total_keys": total,
            "used_keys": used,
            "active_keys": active,
            "total_users": len(users)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/keys', methods=['GET'])
@admin_required
def list_keys():
    try:
        return jsonify(load_data(KEYS_FILE))
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/users', methods=['GET'])
@admin_required
def list_users():
    try:
        return jsonify(load_data(USERS_FILE))
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/devices', methods=['GET'])
@admin_required
def list_devices():
    try:
        return jsonify(load_data(DEVICES_FILE))
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/delete/<key>', methods=['DELETE'])
@admin_required
def delete_key(key):
    try:
        keys = load_data(KEYS_FILE)
        keys = [k for k in keys if k['key'] != key]
        save_data(KEYS_FILE, keys)
        return jsonify({"success": True, "message": "Key deleted"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/clear', methods=['DELETE'])
@admin_required
def clear_all():
    try:
        save_data(KEYS_FILE, [])
        save_data(USERS_FILE, [])
        save_data(DEVICES_FILE, [])
        return jsonify({"success": True, "message": "All data cleared"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# =============================================
# ADMIN AUTH
# =============================================

@app.route('/admin/login', methods=['POST'])
def admin_login():
    try:
        data = request.json
        if data.get('password') == 'admin123':
            session['admin'] = True
            return jsonify({"success": True})
        return jsonify({"success": False}), 401
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin', None)
    return jsonify({"success": True})

# =============================================
# UI
# =============================================

HTML = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HEX KEY SYSTEM</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', sans-serif; background: #0a0a0a; color: #fff; min-height: 100vh; }
        .header { background: linear-gradient(135deg, #00ff88, #00cc66); padding: 20px 40px; display: flex; justify-content: space-between; align-items: center; }
        .header h1 { color: #0a0a0a; font-size: 24px; }
        .header h1 i { margin-right: 10px; }
        .badge { background: #0a0a0a; color: #00ff88; padding: 5px 15px; border-radius: 20px; font-size: 12px; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 30px; }
        .stat { background: #111; border: 1px solid #222; border-radius: 12px; padding: 20px; text-align: center; }
        .stat .num { font-size: 32px; font-weight: 900; color: #00ff88; }
        .stat .label { color: #666; font-size: 12px; text-transform: uppercase; margin-top: 5px; }
        .panel { background: #111; border: 1px solid #222; border-radius: 12px; padding: 25px; margin-bottom: 25px; }
        .panel h3 { color: #00ff88; margin-bottom: 15px; }
        .panel h3 i { margin-right: 10px; }
        .input-group { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
        .input-group input, .input-group select { padding: 10px 15px; background: #1a1a1a; border: 2px solid #222; border-radius: 8px; color: #fff; font-size: 14px; flex: 1; min-width: 80px; }
        .input-group input:focus, .input-group select:focus { outline: none; border-color: #00ff88; }
        .btn { padding: 10px 25px; border: none; border-radius: 8px; font-weight: 700; cursor: pointer; transition: 0.3s; }
        .btn-primary { background: #00ff88; color: #0a0a0a; }
        .btn-primary:hover { transform: scale(1.05); }
        .btn-danger { background: #ff4444; color: #fff; }
        .btn-danger:hover { transform: scale(1.05); }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th { text-align: left; padding: 10px; color: #666; font-size: 11px; text-transform: uppercase; border-bottom: 2px solid #222; }
        td { padding: 10px; border-bottom: 1px solid #1a1a1a; font-size: 13px; }
        tr:hover { background: #0d0d0d; }
        .status-active { color: #00ff88; }
        .status-used { color: #ffaa00; }
        .status-expired { color: #ff4444; }
        .tabs { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }
        .tab { padding: 8px 20px; background: #1a1a1a; border: 2px solid #222; border-radius: 8px; color: #666; cursor: pointer; transition: 0.3s; }
        .tab.active { border-color: #00ff88; color: #00ff88; background: #0a0a0a; }
        .tab:hover { border-color: #00ff88; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .login-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.95); display: flex; justify-content: center; align-items: center; z-index: 9999; }
        .login-box { background: #111; border: 2px solid #222; border-radius: 16px; padding: 40px; width: 90%; max-width: 380px; text-align: center; }
        .login-box h2 { color: #00ff88; margin-bottom: 10px; }
        .login-box p { color: #666; margin-bottom: 20px; }
        .login-box input { width: 100%; padding: 12px; background: #1a1a1a; border: 2px solid #222; border-radius: 8px; color: #fff; margin-bottom: 15px; }
        .login-box input:focus { border-color: #00ff88; outline: none; }
        .login-box .btn { width: 100%; }
        .toast { position: fixed; bottom: 30px; right: 30px; padding: 12px 24px; border-radius: 8px; font-weight: 600; z-index: 10000; animation: slideIn 0.5s; }
        .toast-success { background: #00cc66; color: #0a0a0a; }
        .toast-error { background: #ff4444; color: #fff; }
        @keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
        .footer { text-align: center; padding: 20px; color: #444; font-size: 12px; border-top: 1px solid #111; margin-top: 20px; }
        .key-display { background: #0a0a0a; border: 2px solid #222; border-radius: 8px; padding: 15px; font-family: monospace; font-size: 18px; color: #00ff88; margin: 10px 0; }
        .copy-btn { background: none; border: none; color: #00ff88; cursor: pointer; margin-left: 10px; }
        .copy-btn:hover { color: #fff; }
        .duration-badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 11px; font-weight: 600; }
        .duration-hours { background: #1a3a2a; color: #00ff88; }
        .duration-days { background: #1a2a3a; color: #66aaff; }
        .scrollable { max-height: 400px; overflow-y: auto; }
        .scrollable::-webkit-scrollbar { width: 6px; }
        .scrollable::-webkit-scrollbar-track { background: #0a0a0a; }
        .scrollable::-webkit-scrollbar-thumb { background: #2a2a2a; border-radius: 3px; }
        .scrollable::-webkit-scrollbar-thumb:hover { background: #00ff88; }
        @media (max-width: 768px) { .header { flex-direction: column; gap: 10px; padding: 15px; } .stats { grid-template-columns: repeat(2, 1fr); } .input-group { flex-direction: column; } .input-group input, .input-group select { width: 100%; } }
    </style>
</head>
<body>
<div id="loginOverlay" class="login-overlay">
    <div class="login-box">
        <h2><i class="fas fa-key"></i> HEX KEYS</h2>
        <p>Admin Panel Access</p>
        <input type="password" id="adminPass" placeholder="Enter password" onkeypress="if(event.key==='Enter') login()">
        <button class="btn btn-primary" onclick="login()">Unlock</button>
        <p style="margin-top: 15px; font-size: 11px; color: #444;">Default: admin123</p>
    </div>
</div>
<div id="main" style="display:none;">
    <div class="header">
        <h1><i class="fas fa-key"></i> HEX KEY SYSTEM</h1>
        <span class="badge"><i class="fas fa-bolt"></i> PREMIUM</span>
    </div>
    <div class="container">
        <div class="stats" id="stats">
            <div class="stat"><div class="num" id="totalKeys">0</div><div class="label">Total Keys</div></div>
            <div class="stat"><div class="num" id="activeKeys">0</div><div class="label">Active Keys</div></div>
            <div class="stat"><div class="num" id="usedKeys">0</div><div class="label">Used Keys</div></div>
            <div class="stat"><div class="num" id="totalUsers">0</div><div class="label">Users</div></div>
        </div>
        <div class="panel">
            <h3><i class="fas fa-plus-circle"></i> Generate Keys</h3>
            <div class="input-group">
                <input type="number" id="keyCount" value="1" min="1" max="50" style="max-width:80px;">
                <input type="number" id="durationValue" value="24" min="1" max="9999" style="max-width:100px;">
                <select id="durationType" style="max-width:120px;">
                    <option value="hours">Hours</option>
                    <option value="days">Days</option>
                </select>
                <button class="btn btn-primary" onclick="generateKeys()"><i class="fas fa-wand-magic-sparkles"></i> Generate</button>
            </div>
            <div id="generatedKeys"></div>
        </div>
        <div class="panel">
            <div class="tabs">
                <div class="tab active" onclick="switchTab('keys')"><i class="fas fa-keys"></i> Keys</div>
                <div class="tab" onclick="switchTab('users')"><i class="fas fa-users"></i> Users</div>
                <div class="tab" onclick="switchTab('devices')"><i class="fas fa-laptop"></i> Devices</div>
                <div class="tab" onclick="switchTab('api')"><i class="fas fa-code"></i> API</div>
            </div>
            <div id="tabKeys" class="tab-content active">
                <div class="scrollable">
                    <table>
                        <thead><tr><th>Key</th><th>Duration</th><th>Status</th><th>User</th><th>Device</th><th>Expires</th><th>Action</th></tr></thead>
                        <tbody id="keysTable"></tbody>
                    </table>
                </div>
            </div>
            <div id="tabUsers" class="tab-content">
                <div class="scrollable">
                    <table>
                        <thead><tr><th>Username</th><th>Key</th><th>Device</th><th>Activated</th><th>Expires</th><th>Remaining</th></tr></thead>
                        <tbody id="usersTable"></tbody>
                    </table>
                </div>
            </div>
            <div id="tabDevices" class="tab-content">
                <div class="scrollable">
                    <table>
                        <thead><tr><th>Device ID</th><th>Username</th><th>Key</th><th>Registered</th></tr></thead>
                        <tbody id="devicesTable"></tbody>
                    </table>
                </div>
            </div>
            <div id="tabApi" class="tab-content">
                <div style="background:#0a0a0a; padding:20px; border-radius:8px; border:1px solid #222;">
                    <h4 style="color:#00ff88;">API Endpoints for Java Injector</h4>
                    <div style="margin:15px 0; padding:15px; background:#000; border-radius:6px; font-family:monospace; font-size:13px; color:#aaa;">
                        <p><span style="color:#00ff88;">POST</span> /api/generate - Generate keys</p>
                        <p><span style="color:#ffaa00;">POST</span> /api/activate - Activate key with device</p>
                        <p><span style="color:#ffaa00;">POST</span> /api/verify - Verify key and device</p>
                        <p><span style="color:#00ff88;">GET</span> /api/check?key=KEY&device=DEVICE - Quick check</p>
                        <p><span style="color:#00ff88;">GET</span> /api/stats - System statistics</p>
                    </div>
                    <div style="margin-top:15px; background:#0a0a0a; padding:15px; border-radius:6px; border:1px solid #222;">
                        <p style="color:#888; font-size:13px;"><strong>Activate Example:</strong></p>
                        <pre style="color:#00ff88; font-size:12px; background:#000; padding:10px; border-radius:4px;">
{
  "key": "ABCDEFGHIJKLMNOP",
  "username": "player123",
  "device": "device_fingerprint"
}</pre>
                    </div>
                    <div style="margin-top:10px;">
                        <button class="btn btn-danger" onclick="clearAll()"><i class="fas fa-trash"></i> Clear All Data</button>
                    </div>
                </div>
            </div>
        </div>
        <div class="footer">
            <i class="fas fa-key" style="color:#00ff88;"></i> HEX KEY SYSTEM &bull; 
            <a href="#" onclick="logout()" style="color:#00ff88; text-decoration:none;">Logout</a>
        </div>
    </div>
</div>
<script>
function login() {
    const pass = document.getElementById('adminPass').value;
    fetch('/admin/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: pass })
    })
    .then(res => res.json())
    .then(data => {
        if (data.success) {
            document.getElementById('loginOverlay').style.display = 'none';
            document.getElementById('main').style.display = 'block';
            loadAll();
            toast('Logged in successfully', 'success');
        } else {
            toast('Invalid password', 'error');
        }
    })
    .catch(() => toast('Login error', 'error'));
}

function logout() {
    fetch('/admin/logout').then(() => {
        document.getElementById('loginOverlay').style.display = 'flex';
        document.getElementById('main').style.display = 'none';
    });
}

function loadAll() { loadStats(); loadKeys(); loadUsers(); loadDevices(); }

function loadStats() {
    fetch('/api/stats')
    .then(res => res.json())
    .then(data => {
        document.getElementById('totalKeys').textContent = data.total_keys || 0;
        document.getElementById('activeKeys').textContent = data.active_keys || 0;
        document.getElementById('usedKeys').textContent = data.used_keys || 0;
        document.getElementById('totalUsers').textContent = data.total_users || 0;
    })
    .catch(() => console.log('Stats load error'));
}

function loadKeys() {
    fetch('/api/keys')
    .then(res => res.json())
    .then(data => {
        const tbody = document.getElementById('keysTable');
        tbody.innerHTML = '';
        if (!data || data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color:#444; padding:20px;">No keys generated yet</td></tr>';
            return;
        }
        data.forEach(k => {
            const used = k.used || false;
            const expired = new Date(k.expires) < new Date();
            let statusText = 'ACTIVE', statusCls = 'status-active';
            if (used) { statusText = 'USED'; statusCls = 'status-used'; }
            if (expired && !used) { statusText = 'EXPIRED'; statusCls = 'status-expired'; }
            const durationDisplay = k.duration_type === 'days' 
                ? `<span class="duration-badge duration-days">${k.duration_value}d</span>`
                : `<span class="duration-badge duration-hours">${k.duration_value}h</span>`;
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td style="font-family:monospace; font-size:12px;">${k.key}</td>
                <td>${durationDisplay}</td>
                <td class="${statusCls}">${statusText}</td>
                <td>${k.used_by || '-'}</td>
                <td style="font-family:monospace; font-size:10px;">${k.device ? k.device.substring(0,16)+'...' : '-'}</td>
                <td style="font-size:11px;">${new Date(k.expires).toLocaleDateString()}</td>
                <td><button class="btn btn-danger" style="padding:4px 12px; font-size:11px;" onclick="deleteKey('${k.key}')"><i class="fas fa-trash"></i></button></td>
            `;
            tbody.appendChild(tr);
        });
    })
    .catch(() => console.log('Keys load error'));
}

function loadUsers() {
    fetch('/api/users')
    .then(res => res.json())
    .then(data => {
        const tbody = document.getElementById('usersTable');
        tbody.innerHTML = '';
        if (!data || data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:#444; padding:20px;">No users yet</td></tr>';
            return;
        }
        data.forEach(u => {
            const expired = new Date(u.expires) < new Date();
            const remaining = expired ? 'EXPIRED' : getRemaining(u.expires);
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><strong>${u.username}</strong></td>
                <td style="font-family:monospace; font-size:11px;">${u.key}</td>
                <td style="font-family:monospace; font-size:10px;">${u.device ? u.device.substring(0,16)+'...' : '-'}</td>
                <td style="font-size:11px;">${new Date(u.activated).toLocaleString()}</td>
                <td style="font-size:11px;">${new Date(u.expires).toLocaleDateString()}</td>
                <td style="color:${expired ? '#ff4444' : '#00ff88'}; font-weight:600;">${remaining}</td>
            `;
            tbody.appendChild(tr);
        });
    })
    .catch(() => console.log('Users load error'));
}

function loadDevices() {
    fetch('/api/devices')
    .then(res => res.json())
    .then(data => {
        const tbody = document.getElementById('devicesTable');
        tbody.innerHTML = '';
        if (!data || data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color:#444; padding:20px;">No devices registered</td></tr>';
            return;
        }
        data.forEach(d => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td style="font-family:monospace; font-size:10px;">${d.device_id}</td>
                <td><strong>${d.username}</strong></td>
                <td style="font-family:monospace; font-size:11px;">${d.key}</td>
                <td style="font-size:11px;">${new Date(d.registered).toLocaleString()}</td>
            `;
            tbody.appendChild(tr);
        });
    })
    .catch(() => console.log('Devices load error'));
}

function getRemaining(expires) {
    const diff = new Date(expires) - new Date();
    if (diff <= 0) return 'EXPIRED';
    const days = Math.floor(diff / 86400000);
    const hours = Math.floor((diff % 86400000) / 3600000);
    if (days > 0) return `${days}d ${hours}h`;
    return `${hours}h`;
}

function generateKeys() {
    const count = document.getElementById('keyCount').value || 1;
    const durationValue = document.getElementById('durationValue').value || 24;
    const durationType = document.getElementById('durationType').value;

    fetch('/api/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
            count: parseInt(count), 
            duration_value: parseInt(durationValue),
            duration_type: durationType
        })
    })
    .then(res => res.json())
    .then(data => {
        if (data.success) {
            let html = '<div style="margin-top:15px; display:flex; flex-wrap:wrap; gap:10px;">';
            data.keys.forEach(k => {
                html += `<div class="key-display" style="display:inline-block; padding:10px 15px; font-size:14px;">
                    ${k} <button class="copy-btn" onclick="copyKey('${k}')"><i class="fas fa-copy"></i></button>
                </div>`;
            });
            html += '</div>';
            document.getElementById('generatedKeys').innerHTML = html;
            toast(`Generated ${data.count} key(s)`, 'success');
            loadAll();
        } else {
            toast('Generation failed: ' + (data.error || 'Unknown error'), 'error');
        }
    })
    .catch(err => {
        toast('Generation error: ' + err.message, 'error');
        console.error(err);
    });
}

function deleteKey(key) {
    if (!confirm('Delete this key?')) return;
    fetch(`/api/delete/${key}`, { method: 'DELETE' })
    .then(res => res.json())
    .then(data => {
        if (data.success) { toast('Key deleted', 'success'); loadAll(); }
    })
    .catch(() => toast('Delete error', 'error'));
}

function clearAll() {
    if (!confirm('Clear ALL data? This cannot be undone!')) return;
    fetch('/api/clear', { method: 'DELETE' })
    .then(res => res.json())
    .then(data => {
        if (data.success) { toast('All data cleared', 'success'); loadAll(); }
    })
    .catch(() => toast('Error clearing data', 'error'));
}

function copyKey(key) { navigator.clipboard.writeText(key); toast('Key copied!', 'success'); }

function switchTab(tab) {
    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.tab').forEach(el => el.classList.remove('active'));
    document.getElementById('tabKeys').classList.toggle('active', tab === 'keys');
    document.getElementById('tabUsers').classList.toggle('active', tab === 'users');
    document.getElementById('tabDevices').classList.toggle('active', tab === 'devices');
    document.getElementById('tabApi').classList.toggle('active', tab === 'api');
    document.querySelectorAll('.tab').forEach(el => {
        if (el.textContent.toLowerCase().includes(tab)) el.classList.add('active');
    });
}

function toast(msg, type) {
    const existing = document.querySelector('.toast');
    if (existing) existing.remove();
    const div = document.createElement('div');
    div.className = `toast toast-${type}`;
    div.textContent = msg;
    document.body.appendChild(div);
    setTimeout(() => div.remove(), 3000);
}

setInterval(loadAll, 30000);
</script>
</body>
</html>
'''

@app.route('/')
def admin_panel():
    return render_template_string(HTML)

# =============================================
# RUN
# =============================================

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5005))
    app.run(host='0.0.0.0', port=port, debug=False)