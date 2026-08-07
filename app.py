# app.py - Complete with Device Limit per Key
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
ACTIVITY_FILE = "activity.json"

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

def log_activity(action, details):
    activity = load_data(ACTIVITY_FILE)
    activity.append({
        "timestamp": datetime.now().isoformat(),
        "action": action,
        "details": details
    })
    save_data(ACTIVITY_FILE, activity)

# =============================================
# CHECK KEY ENDPOINT (GET)
# =============================================

@app.route('/api/check', methods=['GET'])
def check_key():
    try:
        key = request.args.get('key')
        device = request.args.get('device')
        
        if not key:
            return jsonify({
                "success": False,
                "error": "Key parameter required",
                "usage": "/api/check?key=YOUR_KEY"
            }), 400
        
        keys = load_data(KEYS_FILE)
        
        for k in keys:
            if k['key'] == key:
                # Check if key is used
                if not k.get('used', False):
                    return jsonify({
                        "success": False,
                        "valid": False,
                        "error": "Key not activated",
                        "status": "INACTIVE",
                        "key": key
                    })
                
                # Check device limit
                if device:
                    devices = load_data(DEVICES_FILE)
                    device_count = sum(1 for d in devices if d['key'] == key)
                    max_devices = k.get('device_limit', 1)
                    
                    # Check if this device is already registered
                    device_registered = any(d['device_id'] == device and d['key'] == key for d in devices)
                    
                    if not device_registered and device_count >= max_devices:
                        return jsonify({
                            "success": False,
                            "valid": False,
                            "error": f"Device limit reached (max {max_devices} devices)",
                            "status": "DEVICE_LIMIT_REACHED",
                            "key": key,
                            "device_limit": max_devices,
                            "current_devices": device_count
                        })
                
                # Check expiry
                expires = datetime.fromisoformat(k['expires'])
                if expires < datetime.now():
                    return jsonify({
                        "success": False,
                        "valid": False,
                        "error": "Key expired",
                        "status": "EXPIRED",
                        "key": key,
                        "expires": k['expires']
                    })
                
                # Calculate remaining
                remaining_seconds = (expires - datetime.now()).total_seconds()
                if k['duration_type'] == 'days':
                    remaining = int(remaining_seconds / 86400)
                    remaining_text = f"{remaining} days"
                else:
                    remaining = int(remaining_seconds / 3600)
                    remaining_text = f"{remaining} hours"
                
                # Get device count
                devices = load_data(DEVICES_FILE)
                device_count = sum(1 for d in devices if d['key'] == key)
                max_devices = k.get('device_limit', 1)
                
                return jsonify({
                    "success": True,
                    "valid": True,
                    "status": "VALID",
                    "key": key,
                    "username": k.get('used_by', 'Unknown'),
                    "device": k.get('device', 'Not registered'),
                    "expires": k['expires'],
                    "remaining": remaining_text,
                    "remaining_hours": int(remaining_seconds / 3600),
                    "duration_type": k['duration_type'],
                    "duration_value": k['duration_value'],
                    "is_custom": k.get('is_custom', False),
                    "device_limit": max_devices,
                    "current_devices": device_count,
                    "devices_remaining": max_devices - device_count
                })
        
        return jsonify({
            "success": False,
            "valid": False,
            "error": "Invalid key",
            "status": "INVALID",
            "key": key
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "valid": False,
            "error": str(e)
        }), 400

# =============================================
# LOGIN ENDPOINT (POST)
# =============================================

@app.route('/api/login', methods=['POST'])
def login_key():
    try:
        data = request.json
        key = data.get('key')
        device = data.get('device') or get_device_id(request)
        
        if not key:
            return jsonify({"success": False, "error": "Key required"}), 400
        
        keys = load_data(KEYS_FILE)
        devices = load_data(DEVICES_FILE)
        
        for k in keys:
            if k['key'] == key:
                if not k['used']:
                    return jsonify({"success": False, "error": "Key not activated", "status": "INACTIVE"}), 400
                
                # Check device limit
                device_count = sum(1 for d in devices if d['key'] == key)
                max_devices = k.get('device_limit', 1)
                device_registered = any(d['device_id'] == device and d['key'] == key for d in devices)
                
                if not device_registered and device_count >= max_devices:
                    return jsonify({
                        "success": False,
                        "error": f"Device limit reached (max {max_devices} devices)",
                        "status": "DEVICE_LIMIT_REACHED",
                        "device_limit": max_devices,
                        "current_devices": device_count
                    }), 400
                
                # If device not registered, add it
                if not device_registered:
                    device_data = {
                        "device_id": device,
                        "username": k['used_by'],
                        "key": key,
                        "registered": datetime.now().isoformat()
                    }
                    devices.append(device_data)
                    save_data(DEVICES_FILE, devices)
                    log_activity("DEVICE_ADDED", {"key": key, "device": device})
                
                # Check expiry
                expires = datetime.fromisoformat(k['expires'])
                if expires < datetime.now():
                    return jsonify({
                        "success": False,
                        "error": "Key expired",
                        "status": "EXPIRED",
                        "expires": k['expires']
                    }), 400
                
                remaining_seconds = (expires - datetime.now()).total_seconds()
                if k['duration_type'] == 'days':
                    remaining_text = f"{int(remaining_seconds / 86400)} days"
                else:
                    remaining_text = f"{int(remaining_seconds / 3600)} hours"
                
                # Get updated device count
                device_count = sum(1 for d in devices if d['key'] == key)
                max_devices = k.get('device_limit', 1)
                
                log_activity("LOGIN", {"key": key, "username": k['used_by'], "device": device})
                
                return jsonify({
                    "success": True,
                    "status": "SUCCESS",
                    "message": "Login successful",
                    "username": k['used_by'],
                    "key": key,
                    "device": device,
                    "expires": k['expires'],
                    "remaining": remaining_text,
                    "remaining_hours": int(remaining_seconds / 3600),
                    "duration_type": k['duration_type'],
                    "duration_value": k['duration_value'],
                    "device_limit": max_devices,
                    "current_devices": device_count,
                    "devices_remaining": max_devices - device_count
                })
        
        return jsonify({"success": False, "error": "Invalid key", "status": "INVALID"}), 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

# =============================================
# GENERATE ENDPOINTS WITH DEVICE LIMIT
# =============================================

@app.route('/api/generate', methods=['POST'])
@admin_required
def generate_keys():
    try:
        data = request.json
        count = int(data.get('count', 1))
        duration_type = data.get('duration_type', 'hours')
        duration_value = int(data.get('duration_value', 24))
        device_limit = int(data.get('device_limit', 1))  # NEW: device limit per key
        
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
                "activated": None,
                "status": "ACTIVE",
                "device_limit": device_limit,  # NEW
                "devices": []  # NEW: list of registered devices
            }
            keys.append(key_data)
            generated.append(key)
        
        save_data(KEYS_FILE, keys)
        log_activity("GENERATE", {
            "count": count, 
            "duration": f"{duration_value} {duration_type}",
            "device_limit": device_limit
        })
        
        return jsonify({
            "success": True,
            "keys": generated,
            "count": count,
            "duration_type": duration_type,
            "duration_value": duration_value,
            "device_limit": device_limit,
            "message": f"Generated {count} key(s) with {device_limit} device(s) limit"
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@app.route('/api/generate/custom', methods=['POST'])
@admin_required
def generate_custom_keys():
    try:
        data = request.json
        custom_keys = data.get('keys', [])
        duration_type = data.get('duration_type', 'hours')
        duration_value = int(data.get('duration_value', 24))
        device_limit = int(data.get('device_limit', 1))  # NEW
        
        if not custom_keys:
            return jsonify({"success": False, "error": "No custom keys provided"}), 400
        
        keys = load_data(KEYS_FILE)
        generated = []
        duplicates = []
        
        for custom_key in custom_keys:
            custom_key = custom_key.strip().upper()
            
            existing = any(k['key'] == custom_key for k in keys)
            if existing:
                duplicates.append(custom_key)
                continue
            
            if duration_type == 'days':
                expires = (datetime.now() + timedelta(days=duration_value)).isoformat()
            else:
                expires = (datetime.now() + timedelta(hours=duration_value)).isoformat()
            
            key_data = {
                "key": custom_key,
                "duration_type": duration_type,
                "duration_value": duration_value,
                "created": datetime.now().isoformat(),
                "expires": expires,
                "used": False,
                "used_by": None,
                "device": None,
                "activated": None,
                "status": "ACTIVE",
                "is_custom": True,
                "device_limit": device_limit,  # NEW
                "devices": []  # NEW
            }
            keys.append(key_data)
            generated.append(custom_key)
        
        save_data(KEYS_FILE, keys)
        log_activity("GENERATE_CUSTOM", {
            "count": len(generated),
            "duplicates": len(duplicates),
            "duration": f"{duration_value} {duration_type}",
            "device_limit": device_limit
        })
        
        return jsonify({
            "success": True,
            "keys": generated,
            "duplicates": duplicates,
            "count": len(generated),
            "duration_type": duration_type,
            "duration_value": duration_value,
            "device_limit": device_limit,
            "message": f"Generated {len(generated)} custom key(s) with {device_limit} device(s) limit"
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

# =============================================
# ACTIVATE ENDPOINT WITH DEVICE LIMIT
# =============================================

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
                    return jsonify({"error": "Key already used", "status": "USED"}), 400
                
                expires = datetime.fromisoformat(k['expires'])
                if expires < datetime.now():
                    return jsonify({"error": "Key expired", "status": "EXPIRED"}), 400
                
                k['used'] = True
                k['used_by'] = username
                k['device'] = device
                k['activated'] = datetime.now().isoformat()
                k['status'] = "ACTIVATED"
                k['devices'] = [device]  # NEW: store first device
                
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
                log_activity("ACTIVATE", {"key": key, "username": username, "device": device})
                
                return jsonify({
                    "success": True,
                    "message": "Key activated successfully",
                    "key": key,
                    "username": username,
                    "device": device,
                    "expires": k['expires'],
                    "status": "ACTIVATED",
                    "device_limit": k.get('device_limit', 1),
                    "current_devices": 1
                })
        
        return jsonify({"error": "Invalid key"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# =============================================
# VERIFY ENDPOINT WITH DEVICE LIMIT
# =============================================

@app.route('/api/verify', methods=['POST'])
def verify_key():
    try:
        data = request.json
        key = data.get('key')
        device = data.get('device') or get_device_id(request)
        
        if not key:
            return jsonify({"error": "Key required"}), 400
        
        keys = load_data(KEYS_FILE)
        devices = load_data(DEVICES_FILE)
        
        for k in keys:
            if k['key'] == key:
                if not k['used']:
                    return jsonify({"valid": False, "error": "Key not activated", "status": "INACTIVE"}), 400
                
                # Check device limit
                device_count = sum(1 for d in devices if d['key'] == key)
                max_devices = k.get('device_limit', 1)
                device_registered = any(d['device_id'] == device and d['key'] == key for d in devices)
                
                if not device_registered and device_count >= max_devices:
                    return jsonify({
                        "valid": False,
                        "error": f"Device limit reached (max {max_devices} devices)",
                        "status": "DEVICE_LIMIT_REACHED",
                        "device_limit": max_devices,
                        "current_devices": device_count
                    }), 400
                
                expires = datetime.fromisoformat(k['expires'])
                if expires < datetime.now():
                    return jsonify({
                        "valid": False,
                        "error": "Key expired",
                        "status": "EXPIRED",
                        "expires": k['expires']
                    }), 400
                
                remaining_seconds = (expires - datetime.now()).total_seconds()
                if k['duration_type'] == 'days':
                    remaining_text = f"{int(remaining_seconds / 86400)} days"
                else:
                    remaining_text = f"{int(remaining_seconds / 3600)} hours"
                
                return jsonify({
                    "valid": True,
                    "status": "VALID",
                    "key": key,
                    "username": k['used_by'],
                    "device": device,
                    "expires": k['expires'],
                    "remaining": remaining_text,
                    "remaining_hours": int(remaining_seconds / 3600),
                    "device_limit": k.get('device_limit', 1),
                    "current_devices": device_count,
                    "devices_remaining": max_devices - device_count
                })
        
        return jsonify({"valid": False, "error": "Invalid key", "status": "INVALID"}), 400
    except Exception as e:
        return jsonify({"valid": False, "error": str(e)}), 400

# =============================================
# ADD DEVICE TO EXISTING KEY (NEW)
# =============================================

@app.route('/api/add/device', methods=['POST'])
def add_device():
    try:
        data = request.json
        key = data.get('key')
        username = data.get('username')
        new_device = data.get('device') or get_device_id(request)
        
        if not key:
            return jsonify({"error": "Key required"}), 400
        
        keys = load_data(KEYS_FILE)
        devices = load_data(DEVICES_FILE)
        
        for k in keys:
            if k['key'] == key:
                if not k['used']:
                    return jsonify({"error": "Key not activated", "status": "INACTIVE"}), 400
                
                # Check if device already registered
                device_registered = any(d['device_id'] == new_device and d['key'] == key for d in devices)
                if device_registered:
                    return jsonify({
                        "error": "Device already registered",
                        "status": "DEVICE_EXISTS"
                    }), 400
                
                # Check device limit
                device_count = sum(1 for d in devices if d['key'] == key)
                max_devices = k.get('device_limit', 1)
                
                if device_count >= max_devices:
                    return jsonify({
                        "error": f"Device limit reached (max {max_devices} devices)",
                        "status": "DEVICE_LIMIT_REACHED",
                        "device_limit": max_devices,
                        "current_devices": device_count
                    }), 400
                
                # Add new device
                device_data = {
                    "device_id": new_device,
                    "username": username or k['used_by'],
                    "key": key,
                    "registered": datetime.now().isoformat()
                }
                devices.append(device_data)
                save_data(DEVICES_FILE, devices)
                
                # Update key devices list
                if 'devices' not in k:
                    k['devices'] = []
                k['devices'].append(new_device)
                save_data(KEYS_FILE, keys)
                
                log_activity("DEVICE_ADDED", {"key": key, "device": new_device})
                
                return jsonify({
                    "success": True,
                    "message": "Device added successfully",
                    "key": key,
                    "device": new_device,
                    "device_limit": k.get('device_limit', 1),
                    "current_devices": device_count + 1,
                    "devices_remaining": max_devices - (device_count + 1)
                })
        
        return jsonify({"error": "Invalid key"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# =============================================
# GET KEY DEVICES (NEW)
# =============================================

@app.route('/api/key/devices', methods=['GET'])
def get_key_devices():
    try:
        key = request.args.get('key')
        
        if not key:
            return jsonify({"error": "Key required"}), 400
        
        keys = load_data(KEYS_FILE)
        devices = load_data(DEVICES_FILE)
        
        for k in keys:
            if k['key'] == key:
                key_devices = [d for d in devices if d['key'] == key]
                return jsonify({
                    "key": key,
                    "device_limit": k.get('device_limit', 1),
                    "current_devices": len(key_devices),
                    "devices": key_devices,
                    "devices_remaining": k.get('device_limit', 1) - len(key_devices)
                })
        
        return jsonify({"error": "Invalid key"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# =============================================
# REMOVE DEVICE FROM KEY (NEW)
# =============================================

@app.route('/api/remove/device', methods=['POST'])
@admin_required
def remove_device():
    try:
        data = request.json
        key = data.get('key')
        device = data.get('device')
        
        if not key or not device:
            return jsonify({"error": "Key and device required"}), 400
        
        devices = load_data(DEVICES_FILE)
        devices = [d for d in devices if not (d['key'] == key and d['device_id'] == device)]
        save_data(DEVICES_FILE, devices)
        
        # Update key devices list
        keys = load_data(KEYS_FILE)
        for k in keys:
            if k['key'] == key and 'devices' in k:
                if device in k['devices']:
                    k['devices'].remove(device)
                save_data(KEYS_FILE, keys)
                break
        
        log_activity("DEVICE_REMOVED", {"key": key, "device": device})
        
        return jsonify({
            "success": True,
            "message": "Device removed successfully",
            "key": key,
            "device": device
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# =============================================
# STATS ENDPOINT
# =============================================

@app.route('/api/stats', methods=['GET'])
def get_stats():
    try:
        keys = load_data(KEYS_FILE)
        users = load_data(USERS_FILE)
        devices = load_data(DEVICES_FILE)
        
        total = len(keys)
        used = sum(1 for k in keys if k.get('used', False))
        active = total - used
        expired = sum(1 for k in keys if datetime.fromisoformat(k['expires']) < datetime.now())
        custom = sum(1 for k in keys if k.get('is_custom', False))
        
        # Total device limit across all keys
        total_device_limit = sum(k.get('device_limit', 1) for k in keys)
        total_devices_registered = len(devices)
        
        return jsonify({
            "total_keys": total,
            "used_keys": used,
            "active_keys": active,
            "expired_keys": expired,
            "custom_keys": custom,
            "total_users": len(users),
            "total_devices": len(devices),
            "total_device_limit": total_device_limit,
            "devices_registered": total_devices_registered
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# =============================================
# LIST KEYS WITH DEVICE INFO
# =============================================

@app.route('/api/keys', methods=['GET'])
@admin_required
def list_keys():
    try:
        keys = load_data(KEYS_FILE)
        devices = load_data(DEVICES_FILE)
        
        for k in keys:
            expires = datetime.fromisoformat(k['expires'])
            if k.get('used', False):
                if expires < datetime.now():
                    k['status_display'] = "EXPIRED"
                else:
                    k['status_display'] = "ACTIVE"
            else:
                if expires < datetime.now():
                    k['status_display'] = "EXPIRED"
                else:
                    k['status_display'] = "UNUSED"
            
            if k.get('is_custom', False):
                k['status_display'] += " ✏️"
            
            # Add device info
            key_devices = [d for d in devices if d['key'] == k['key']]
            k['current_devices'] = len(key_devices)
            k['device_limit'] = k.get('device_limit', 1)
            k['devices_remaining'] = k['device_limit'] - len(key_devices)
        
        return jsonify(keys)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# =============================================
# OTHER ENDPOINTS
# =============================================

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

@app.route('/api/activity', methods=['GET'])
@admin_required
def list_activity():
    try:
        return jsonify(load_data(ACTIVITY_FILE))
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/delete/<key>', methods=['DELETE'])
@admin_required
def delete_key(key):
    try:
        keys = load_data(KEYS_FILE)
        keys = [k for k in keys if k['key'] != key]
        save_data(KEYS_FILE, keys)
        
        # Remove associated devices
        devices = load_data(DEVICES_FILE)
        devices = [d for d in devices if d['key'] != key]
        save_data(DEVICES_FILE, devices)
        
        log_activity("DELETE", {"key": key})
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
        save_data(ACTIVITY_FILE, [])
        log_activity("CLEAR_ALL", {})
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
            log_activity("ADMIN_LOGIN", {})
            return jsonify({"success": True})
        return jsonify({"success": False}), 401
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin', None)
    log_activity("ADMIN_LOGOUT", {})
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
    <title>HEX KEY SYSTEM PREMIUM</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', sans-serif; background: #0a0a0a; color: #fff; min-height: 100vh; }
        .header { background: linear-gradient(135deg, #00ff88, #00cc66); padding: 20px 40px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; }
        .header h1 { color: #0a0a0a; font-size: 24px; }
        .header h1 i { margin-right: 10px; }
        .badge { background: #0a0a0a; color: #00ff88; padding: 5px 15px; border-radius: 20px; font-size: 12px; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 30px; }
        .stat { background: #111; border: 1px solid #222; border-radius: 12px; padding: 20px; text-align: center; transition: 0.3s; }
        .stat:hover { border-color: #00ff88; transform: translateY(-3px); }
        .stat .num { font-size: 32px; font-weight: 900; color: #00ff88; }
        .stat .label { color: #666; font-size: 12px; text-transform: uppercase; margin-top: 5px; }
        .stat .sub { font-size: 11px; color: #444; margin-top: 3px; }
        .panel { background: #111; border: 1px solid #222; border-radius: 12px; padding: 25px; margin-bottom: 25px; }
        .panel h3 { color: #00ff88; margin-bottom: 15px; }
        .panel h3 i { margin-right: 10px; }
        .panel h3 .custom-badge { font-size: 12px; color: #ffaa00; background: #1a1a1a; padding: 2px 12px; border-radius: 12px; margin-left: 10px; }
        .input-group { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
        .input-group input, .input-group select { padding: 10px 15px; background: #1a1a1a; border: 2px solid #222; border-radius: 8px; color: #fff; font-size: 14px; flex: 1; min-width: 80px; }
        .input-group input:focus, .input-group select:focus { outline: none; border-color: #00ff88; }
        .input-group textarea { padding: 10px 15px; background: #1a1a1a; border: 2px solid #222; border-radius: 8px; color: #fff; font-size: 13px; flex: 1; min-width: 200px; font-family: monospace; resize: vertical; }
        .input-group textarea:focus { outline: none; border-color: #00ff88; }
        .btn { padding: 10px 25px; border: none; border-radius: 8px; font-weight: 700; cursor: pointer; transition: 0.3s; }
        .btn-primary { background: #00ff88; color: #0a0a0a; }
        .btn-primary:hover { transform: scale(1.05); box-shadow: 0 0 20px rgba(0,255,136,0.3); }
        .btn-custom { background: #ffaa00; color: #0a0a0a; }
        .btn-custom:hover { transform: scale(1.05); box-shadow: 0 0 20px rgba(255,170,0,0.3); }
        .btn-danger { background: #ff4444; color: #fff; }
        .btn-danger:hover { transform: scale(1.05); }
        .btn-outline { background: transparent; border: 2px solid #222; color: #fff; }
        .btn-outline:hover { border-color: #00ff88; color: #00ff88; }
        .btn-sm { padding: 5px 12px; font-size: 11px; }
        .btn-info { background: #3399ff; color: #fff; }
        .btn-info:hover { transform: scale(1.05); }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 13px; }
        th { text-align: left; padding: 10px; color: #666; font-size: 11px; text-transform: uppercase; border-bottom: 2px solid #222; }
        td { padding: 10px; border-bottom: 1px solid #1a1a1a; }
        tr:hover { background: #0d0d0d; }
        .status-active { color: #00ff88; }
        .status-used { color: #ffaa00; }
        .status-expired { color: #ff4444; }
        .status-inactive { color: #666; }
        .custom-tag { background: #ffaa00; color: #0a0a0a; padding: 1px 8px; border-radius: 10px; font-size: 9px; font-weight: 700; }
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
        .toast-info { background: #3399ff; color: #fff; }
        @keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
        .footer { text-align: center; padding: 20px; color: #444; font-size: 12px; border-top: 1px solid #111; margin-top: 20px; }
        .key-display { background: #0a0a0a; border: 2px solid #222; border-radius: 8px; padding: 15px; font-family: monospace; font-size: 18px; color: #00ff88; margin: 10px 0; display: inline-block; }
        .copy-btn { background: none; border: none; color: #00ff88; cursor: pointer; margin-left: 10px; }
        .copy-btn:hover { color: #fff; }
        .duration-badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 11px; font-weight: 600; }
        .duration-hours { background: #1a3a2a; color: #00ff88; }
        .duration-days { background: #1a2a3a; color: #66aaff; }
        .device-badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 10px; background: #1a2a3a; color: #66aaff; }
        .device-limit-full { color: #ff4444; }
        .device-limit-available { color: #00ff88; }
        .scrollable { max-height: 500px; overflow-y: auto; }
        .scrollable::-webkit-scrollbar { width: 6px; }
        .scrollable::-webkit-scrollbar-track { background: #0a0a0a; }
        .scrollable::-webkit-scrollbar-thumb { background: #2a2a2a; border-radius: 3px; }
        .scrollable::-webkit-scrollbar-thumb:hover { background: #00ff88; }
        @media (max-width: 768px) { .header { flex-direction: column; gap: 10px; padding: 15px; } .stats { grid-template-columns: repeat(2, 1fr); } .input-group { flex-direction: column; } .input-group input, .input-group select, .input-group textarea { width: 100%; } }
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
        <h1><i class="fas fa-crown"></i> HEX KEY SYSTEM PREMIUM</h1>
        <span class="badge"><i class="fas fa-bolt"></i> v3.0</span>
    </div>
    <div class="container">
        <div class="stats" id="stats">
            <div class="stat"><div class="num" id="totalKeys">0</div><div class="label">Total Keys</div></div>
            <div class="stat"><div class="num" id="activeKeys">0</div><div class="label">Active Keys</div></div>
            <div class="stat"><div class="num" id="usedKeys">0</div><div class="label">Used Keys</div></div>
            <div class="stat"><div class="num" id="expiredKeys">0</div><div class="label">Expired Keys</div></div>
            <div class="stat"><div class="num" id="customKeys">0</div><div class="label">Custom Keys</div></div>
            <div class="stat"><div class="num" id="totalUsers">0</div><div class="label">Users</div></div>
            <div class="stat"><div class="num" id="totalDevices">0</div><div class="label">Devices</div></div>
        </div>

        <div class="panel">
            <h3><i class="fas fa-robot"></i> Auto Generate Keys</h3>
            <div class="input-group">
                <input type="number" id="keyCount" value="1" min="1" max="50" style="max-width:70px;">
                <input type="number" id="durationValue" value="24" min="1" max="9999" style="max-width:80px;">
                <select id="durationType" style="max-width:100px;">
                    <option value="hours">Hours</option>
                    <option value="days">Days</option>
                </select>
                <input type="number" id="deviceLimit" value="1" min="1" max="10" style="max-width:70px;" placeholder="Devices">
                <button class="btn btn-primary" onclick="generateKeys()"><i class="fas fa-wand-magic-sparkles"></i> Generate</button>
            </div>
            <div id="generatedKeys"></div>
        </div>

        <div class="panel" style="border-color: #ffaa00;">
            <h3><i class="fas fa-pen"></i> Custom Key Generation <span class="custom-badge">✏️ YOUR KEYS</span></h3>
            <div class="input-group">
                <textarea id="customKeysText" rows="3" placeholder="MYKEY123&#10;VIPKEY456&#10;PREMIUM789" style="flex:2;"></textarea>
                <div style="display:flex; flex-direction:column; gap:8px; flex:1; min-width:150px;">
                    <div style="display:flex; gap:8px; flex-wrap:wrap;">
                        <input type="number" id="customDurationValue" value="24" min="1" max="9999" style="flex:1; min-width:60px;">
                        <select id="customDurationType" style="flex:1; min-width:80px;">
                            <option value="hours">Hours</option>
                            <option value="days">Days</option>
                        </select>
                        <input type="number" id="customDeviceLimit" value="1" min="1" max="10" style="flex:1; min-width:60px;" placeholder="Devices">
                    </div>
                    <button class="btn btn-custom" onclick="generateCustomKeys()"><i class="fas fa-plus"></i> Add Custom Keys</button>
                </div>
            </div>
            <div id="customGeneratedKeys"></div>
        </div>

        <div class="panel">
            <div class="tabs">
                <div class="tab active" onclick="switchTab('keys')"><i class="fas fa-keys"></i> Keys</div>
                <div class="tab" onclick="switchTab('users')"><i class="fas fa-users"></i> Users</div>
                <div class="tab" onclick="switchTab('devices')"><i class="fas fa-laptop"></i> Devices</div>
                <div class="tab" onclick="switchTab('api')"><i class="fas fa-code"></i> API</div>
                <div class="tab" onclick="switchTab('activity')"><i class="fas fa-history"></i> Activity</div>
            </div>
            <div id="tabKeys" class="tab-content active">
                <div class="scrollable">
                    <table>
                        <thead><tr><th>Key</th><th>Duration</th><th>Devices</th><th>Status</th><th>User</th><th>Expires</th><th>Action</th></tr></thead>
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
                    <h4 style="color:#00ff88;"><i class="fas fa-plug"></i> API Endpoints</h4>
                    <div class="api-example">
                        <p><span class="method">GET</span> /api/check?key=KEY - Check key status</p>
                        <p><span class="method">POST</span> /api/login - Login with key and device</p>
                        <p><span class="method">POST</span> /api/activate - Activate key</p>
                        <p><span class="method">POST</span> /api/add/device - Add device to key</p>
                        <p><span class="method">GET</span> /api/key/devices?key=KEY - Get key devices</p>
                        <p><span class="method">POST</span> /api/generate - Generate keys (admin)</p>
                        <p><span class="method">POST</span> /api/generate/custom - Add custom keys (admin)</p>
                    </div>
                </div>
            </div>
            <div id="tabActivity" class="tab-content">
                <div class="scrollable">
                    <table>
                        <thead><tr><th>Time</th><th>Action</th><th>Details</th></tr></thead>
                        <tbody id="activityTable"></tbody>
                    </table>
                </div>
            </div>
        </div>
        <div class="footer">
            <i class="fas fa-crown" style="color:#00ff88;"></i> HEX KEY SYSTEM PREMIUM v3.0 &bull; 
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

function loadAll() { loadStats(); loadKeys(); loadUsers(); loadDevices(); loadActivity(); }

function loadStats() {
    fetch('/api/stats')
    .then(res => res.json())
    .then(data => {
        document.getElementById('totalKeys').textContent = data.total_keys || 0;
        document.getElementById('activeKeys').textContent = data.active_keys || 0;
        document.getElementById('usedKeys').textContent = data.used_keys || 0;
        document.getElementById('expiredKeys').textContent = data.expired_keys || 0;
        document.getElementById('customKeys').textContent = data.custom_keys || 0;
        document.getElementById('totalUsers').textContent = data.total_users || 0;
        document.getElementById('totalDevices').textContent = data.total_devices || 0;
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
            const status = k.status_display || 'UNKNOWN';
            let statusClass = 'status-inactive';
            if (status.includes('ACTIVE')) statusClass = 'status-active';
            else if (status.includes('UNUSED')) statusClass = 'status-active';
            else if (status.includes('EXPIRED')) statusClass = 'status-expired';
            else if (status.includes('USED')) statusClass = 'status-used';
            
            const isCustom = k.is_custom || false;
            const customTag = isCustom ? '<span class="custom-tag">✏️</span>' : '';
            
            const durationDisplay = k.duration_type === 'days' 
                ? `<span class="duration-badge duration-days">${k.duration_value}d</span>`
                : `<span class="duration-badge duration-hours">${k.duration_value}h</span>`;
            
            const deviceLimit = k.device_limit || 1;
            const currentDevices = k.current_devices || 0;
            const devicesRemaining = k.devices_remaining || 0;
            const deviceDisplay = `${currentDevices}/${deviceLimit}`;
            const deviceClass = currentDevices >= deviceLimit ? 'device-limit-full' : 'device-limit-available';
            
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td style="font-family:monospace; font-size:12px;">${k.key} ${customTag}</td>
                <td>${durationDisplay}</td>
                <td class="${deviceClass}">${deviceDisplay}</td>
                <td class="${statusClass}">${status}</td>
                <td>${k.used_by || '-'}</td>
                <td style="font-size:11px;">${new Date(k.expires).toLocaleString()}</td>
                <td><button class="btn btn-danger btn-sm" onclick="deleteKey('${k.key}')"><i class="fas fa-trash"></i></button></td>
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
                <td style="font-size:11px;">${new Date(u.expires).toLocaleString()}</td>
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

function loadActivity() {
    fetch('/api/activity')
    .then(res => res.json())
    .then(data => {
        const tbody = document.getElementById('activityTable');
        tbody.innerHTML = '';
        if (!data || data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="3" style="text-align:center; color:#444; padding:20px;">No activity yet</td></tr>';
            return;
        }
        data.slice(-20).reverse().forEach(a => {
            const tr = document.createElement('tr');
            const details = typeof a.details === 'string' ? a.details : JSON.stringify(a.details);
            tr.innerHTML = `
                <td style="font-size:11px;">${new Date(a.timestamp).toLocaleString()}</td>
                <td><span class="status-active">${a.action}</span></td>
                <td style="font-size:12px; color:#888;">${details}</td>
            `;
            tbody.appendChild(tr);
        });
    })
    .catch(() => console.log('Activity load error'));
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
    const deviceLimit = document.getElementById('deviceLimit').value || 1;

    fetch('/api/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
            count: parseInt(count), 
            duration_value: parseInt(durationValue),
            duration_type: durationType,
            device_limit: parseInt(deviceLimit)
        })
    })
    .then(res => res.json())
    .then(data => {
        if (data.success) {
            let html = '<div style="margin-top:15px; display:flex; flex-wrap:wrap; gap:10px;">';
            data.keys.forEach(k => {
                html += `<div class="key-display">${k} <button class="copy-btn" onclick="copyKey('${k}')"><i class="fas fa-copy"></i></button></div>`;
            });
            html += `<div style="width:100%; color:#888; font-size:12px; margin-top:5px;">Device limit: ${data.device_limit} device(s) per key</div>`;
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

function generateCustomKeys() {
    const keysText = document.getElementById('customKeysText').value;
    const durationValue = document.getElementById('customDurationValue').value || 24;
    const durationType = document.getElementById('customDurationType').value;
    const deviceLimit = document.getElementById('customDeviceLimit').value || 1;

    if (!keysText.trim()) {
        toast('Please enter at least one custom key', 'error');
        return;
    }

    const keys = keysText.split('\\n').map(k => k.trim().toUpperCase()).filter(k => k);

    if (keys.length === 0) {
        toast('No valid keys found', 'error');
        return;
    }

    fetch('/api/generate/custom', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
            keys: keys,
            duration_value: parseInt(durationValue),
            duration_type: durationType,
            device_limit: parseInt(deviceLimit)
        })
    })
    .then(res => res.json())
    .then(data => {
        if (data.success) {
            let html = '<div style="margin-top:15px; display:flex; flex-wrap:wrap; gap:10px;">';
            data.keys.forEach(k => {
                html += `<div class="key-display" style="border-color:#ffaa00;">${k} <span class="custom-tag">✏️</span> <button class="copy-btn" onclick="copyKey('${k}')"><i class="fas fa-copy"></i></button></div>`;
            });
            if (data.duplicates && data.duplicates.length > 0) {
                html += `<div style="color:#ffaa00; font-size:12px; margin-top:10px;">⚠️ Duplicates skipped: ${data.duplicates.join(', ')}</div>`;
            }
            html += `<div style="width:100%; color:#888; font-size:12px; margin-top:5px;">Device limit: ${data.device_limit} device(s) per key</div>`;
            html += '</div>';
            document.getElementById('customGeneratedKeys').innerHTML = html;
            document.getElementById('customKeysText').value = '';
            toast(`Added ${data.count} custom key(s)`, 'success');
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
    document.getElementById('tabActivity').classList.toggle('active', tab === 'activity');
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