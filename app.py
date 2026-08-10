# app.py - Persistent PostgreSQL with debugging
import os
import json
import hashlib
import secrets
import string
import re
import sys
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template_string, session
from flask_cors import CORS
from functools import wraps
from sqlalchemy import create_engine, Column, String, Boolean, DateTime, Integer, JSON, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import func

app = Flask(__name__)
app.secret_key = "HEX_KEYS_SUPREME_SECURE_2026"
CORS(app)

# =============================================
# DATABASE SETUP WITH VERIFICATION
# =============================================

DATABASE_URL = os.environ.get('DATABASE_URL')
if not DATABASE_URL:
    print("❌ ERROR: DATABASE_URL environment variable not set!", file=sys.stderr)
    print("   Please add a PostgreSQL database in Railway and redeploy.", file=sys.stderr)
    # Fallback to SQLite for local testing only
    DATABASE_URL = 'sqlite:///keys.db'
    print("⚠️  Using SQLite fallback – data will NOT persist on Railway!", file=sys.stderr)

print(f"🔗 Connecting to database: {DATABASE_URL[:30]}...")

try:
    engine = create_engine(DATABASE_URL)
    # Test connection
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
    print("✅ Database connection successful!")
except Exception as e:
    print(f"❌ Database connection failed: {e}", file=sys.stderr)
    sys.exit(1)

SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# =============================================
# MODELS
# =============================================

class Key(Base):
    __tablename__ = 'keys'
    key = Column(String(32), primary_key=True)
    duration_type = Column(String(10))
    duration_value = Column(Integer)
    created = Column(DateTime, default=func.now())
    expires = Column(DateTime)
    used = Column(Boolean, default=False)
    activated = Column(DateTime, nullable=True)
    status = Column(String(20), default='ACTIVE')
    is_custom = Column(Boolean, default=False)
    device_limit = Column(Integer, default=1)

class Device(Base):
    __tablename__ = 'devices'
    id = Column(Integer, primary_key=True)
    device_id = Column(String(64), nullable=False)
    key = Column(String(32), nullable=False)
    registered = Column(DateTime, default=func.now())

class Activity(Base):
    __tablename__ = 'activity'
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=func.now())
    action = Column(String(50))
    details = Column(JSON)

# Create tables
print("📦 Creating tables if they don't exist...")
Base.metadata.create_all(engine)
print("✅ Tables ready.")

# =============================================
# HELPERS
# =============================================

def sanitize_key(key):
    if not key:
        return None
    return re.sub(r'[^A-Z0-9]', '', key.upper().strip())

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
    session_db = SessionLocal()
    try:
        activity = Activity(action=action, details=details)
        session_db.add(activity)
        session_db.commit()
    except Exception as e:
        session_db.rollback()
        print(f"⚠️ Failed to log activity: {e}", file=sys.stderr)
    finally:
        session_db.close()

# =============================================
# DB CHECK ENDPOINT (for debugging)
# =============================================

@app.route('/db-check', methods=['GET'])
def db_check():
    try:
        session_db = SessionLocal()
        result = session_db.execute(text("SELECT 1")).scalar()
        session_db.close()
        return jsonify({"status": "ok", "message": "Database connected", "result": result})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# =============================================
# API ENDPOINTS (responses unchanged)
# =============================================

@app.route('/api/login', methods=['POST'])
def login_key():
    try:
        data = request.json
        key = sanitize_key(data.get('key'))
        device = data.get('device') or get_device_id(request)

        if not key:
            return jsonify({"success": False, "status": "ERROR", "message": "Key is required"}), 400
        if not device or len(device) < 5:
            return jsonify({"success": False, "status": "ERROR", "message": "Valid device ID is required"}), 400

        session_db = SessionLocal()
        db_key = session_db.query(Key).filter_by(key=key).first()
        if not db_key:
            session_db.close()
            return jsonify({"success": False, "status": "INVALID", "message": "Invalid key"}), 400

        if not db_key.used:
            session_db.close()
            return jsonify({"success": False, "status": "INACTIVE", "message": "Key not activated. Please activate first."}), 400

        if db_key.expires < datetime.now():
            session_db.close()
            return jsonify({
                "success": False,
                "status": "EXPIRED",
                "message": "Key has expired",
                "expires": db_key.expires.isoformat()
            }), 400

        device_exists = session_db.query(Device).filter_by(device_id=device, key=key).first()
        device_count = session_db.query(Device).filter_by(key=key).count()
        max_devices = db_key.device_limit

        if device_exists:
            log_activity("LOGIN_SUCCESS", {"key": key, "device": device})
            remaining = (db_key.expires - datetime.now()).total_seconds() // 3600
            return jsonify({
                "success": True,
                "status": "SUCCESS",
                "message": "Login successful",
                "key": key,
                "device": device,
                "expires": db_key.expires.isoformat(),
                "remaining_hours": int(remaining),
                "duration_type": db_key.duration_type,
                "duration_value": db_key.duration_value
            })
        else:
            if device_count >= max_devices:
                session_db.close()
                return jsonify({
                    "success": False,
                    "status": "DEVICE_LIMIT_REACHED",
                    "message": f"Device limit reached (max {max_devices} devices)",
                    "device_limit": max_devices,
                    "current_devices": device_count
                }), 400

            new_device = Device(device_id=device, key=key)
            session_db.add(new_device)
            session_db.commit()
            log_activity("DEVICE_AUTO_REGISTER", {"key": key, "device": device})

            remaining = (db_key.expires - datetime.now()).total_seconds() // 3600
            return jsonify({
                "success": True,
                "status": "SUCCESS",
                "message": "Device registered and login successful",
                "key": key,
                "device": device,
                "expires": db_key.expires.isoformat(),
                "remaining_hours": int(remaining),
                "duration_type": db_key.duration_type,
                "duration_value": db_key.duration_value,
                "device_limit": max_devices,
                "current_devices": device_count + 1,
                "devices_remaining": max_devices - (device_count + 1)
            })
    except Exception as e:
        print(f"❌ Login error: {e}", file=sys.stderr)
        return jsonify({"success": False, "status": "ERROR", "message": str(e)}), 500
    finally:
        session_db.close()

@app.route('/api/activate', methods=['POST'])
def activate_key():
    try:
        data = request.json
        key = sanitize_key(data.get('key'))
        device = data.get('device') or get_device_id(request)

        if not key:
            return jsonify({"success": False, "status": "ERROR", "message": "Key is required"}), 400

        session_db = SessionLocal()
        db_key = session_db.query(Key).filter_by(key=key).first()
        if not db_key:
            session_db.close()
            return jsonify({"success": False, "status": "INVALID", "message": "Invalid key"}), 400

        if db_key.used:
            session_db.close()
            return jsonify({"success": False, "status": "ALREADY_ACTIVATED", "message": "Key already activated"}), 400

        if db_key.expires < datetime.now():
            session_db.close()
            return jsonify({"success": False, "status": "EXPIRED", "message": "Key has expired"}), 400

        db_key.used = True
        db_key.activated = datetime.now()
        db_key.status = "ACTIVATED"

        new_device = Device(device_id=device, key=key)
        session_db.add(new_device)
        session_db.commit()

        log_activity("KEY_ACTIVATED", {"key": key, "device": device})

        return jsonify({
            "success": True,
            "status": "ACTIVATED",
            "message": "Key activated successfully",
            "key": key,
            "device": device,
            "expires": db_key.expires.isoformat(),
            "device_limit": db_key.device_limit
        })
    except Exception as e:
        print(f"❌ Activate error: {e}", file=sys.stderr)
        return jsonify({"success": False, "status": "ERROR", "message": str(e)}), 500
    finally:
        session_db.close()

@app.route('/api/check', methods=['GET'])
def check_key():
    try:
        key = sanitize_key(request.args.get('key'))
        device = request.args.get('device')

        if not key:
            return jsonify({"success": False, "status": "ERROR", "message": "Key required"}), 400

        session_db = SessionLocal()
        db_key = session_db.query(Key).filter_by(key=key).first()
        if not db_key:
            session_db.close()
            return jsonify({"success": False, "status": "INVALID", "message": "Invalid key"}), 400

        if not db_key.used:
            session_db.close()
            return jsonify({"success": False, "status": "INACTIVE", "message": "Key not activated"}), 400

        if db_key.expires < datetime.now():
            session_db.close()
            return jsonify({"success": False, "status": "EXPIRED", "message": "Key expired"}), 400

        if device:
            device_exists = session_db.query(Device).filter_by(device_id=device, key=key).first()
            if not device_exists:
                session_db.close()
                return jsonify({"success": False, "status": "DEVICE_NOT_FOUND", "message": "Device not registered"}), 400

        device_count = session_db.query(Device).filter_by(key=key).count()
        remaining = (db_key.expires - datetime.now()).total_seconds() // 3600

        return jsonify({
            "success": True,
            "status": "VALID",
            "key": key,
            "expires": db_key.expires.isoformat(),
            "remaining_hours": int(remaining),
            "device_limit": db_key.device_limit,
            "current_devices": device_count,
            "devices_remaining": db_key.device_limit - device_count
        })
    except Exception as e:
        print(f"❌ Check error: {e}", file=sys.stderr)
        return jsonify({"success": False, "status": "ERROR", "message": str(e)}), 500
    finally:
        session_db.close()

# =============================================
# GENERATE & ADMIN ENDPOINTS (unchanged)
# =============================================

@app.route('/api/generate', methods=['POST'])
@admin_required
def generate_keys():
    try:
        data = request.json
        count = int(data.get('count', 1))
        duration_type = data.get('duration_type', 'hours')
        duration_value = int(data.get('duration_value', 24))
        device_limit = int(data.get('device_limit', 1))

        session_db = SessionLocal()
        generated = []

        for _ in range(count):
            key = generate_key()
            if duration_type == 'days':
                expires = datetime.now() + timedelta(days=duration_value)
            else:
                expires = datetime.now() + timedelta(hours=duration_value)

            new_key = Key(
                key=key,
                duration_type=duration_type,
                duration_value=duration_value,
                expires=expires,
                used=False,
                status="ACTIVE",
                device_limit=device_limit
            )
            session_db.add(new_key)
            generated.append(key)

        session_db.commit()
        log_activity("GENERATE", {"count": count, "duration": f"{duration_value} {duration_type}", "device_limit": device_limit})

        return jsonify({
            "success": True,
            "keys": generated,
            "count": count,
            "duration_type": duration_type,
            "duration_value": duration_value,
            "device_limit": device_limit
        })
    except Exception as e:
        print(f"❌ Generate error: {e}", file=sys.stderr)
        return jsonify({"success": False, "error": str(e)}), 400
    finally:
        session_db.close()

@app.route('/api/generate/custom', methods=['POST'])
@admin_required
def generate_custom_keys():
    try:
        data = request.json
        custom_keys = data.get('keys', [])
        duration_type = data.get('duration_type', 'hours')
        duration_value = int(data.get('duration_value', 24))
        device_limit = int(data.get('device_limit', 1))

        if not custom_keys:
            return jsonify({"success": False, "error": "No custom keys provided"}), 400

        session_db = SessionLocal()
        generated = []
        duplicates = []

        for custom_key in custom_keys:
            clean_key = sanitize_key(custom_key)
            if not clean_key:
                continue

            existing = session_db.query(Key).filter_by(key=clean_key).first()
            if existing:
                duplicates.append(clean_key)
                continue

            if duration_type == 'days':
                expires = datetime.now() + timedelta(days=duration_value)
            else:
                expires = datetime.now() + timedelta(hours=duration_value)

            new_key = Key(
                key=clean_key,
                duration_type=duration_type,
                duration_value=duration_value,
                expires=expires,
                used=False,
                status="ACTIVE",
                is_custom=True,
                device_limit=device_limit
            )
            session_db.add(new_key)
            generated.append(clean_key)

        session_db.commit()
        log_activity("GENERATE_CUSTOM", {"count": len(generated), "duplicates": len(duplicates), "duration": f"{duration_value} {duration_type}", "device_limit": device_limit})

        return jsonify({
            "success": True,
            "keys": generated,
            "duplicates": duplicates,
            "count": len(generated),
            "duration_type": duration_type,
            "duration_value": duration_value,
            "device_limit": device_limit
        })
    except Exception as e:
        print(f"❌ Generate custom error: {e}", file=sys.stderr)
        return jsonify({"success": False, "error": str(e)}), 400
    finally:
        session_db.close()

@app.route('/api/add/device', methods=['POST'])
def add_device():
    try:
        data = request.json
        key = sanitize_key(data.get('key'))
        device = data.get('device') or get_device_id(request)

        if not key:
            return jsonify({"success": False, "status": "ERROR", "message": "Key required"}), 400

        session_db = SessionLocal()
        db_key = session_db.query(Key).filter_by(key=key).first()
        if not db_key:
            session_db.close()
            return jsonify({"success": False, "status": "INVALID", "message": "Invalid key"}), 400

        if not db_key.used:
            session_db.close()
            return jsonify({"success": False, "status": "INACTIVE", "message": "Key not activated"}), 400

        device_exists = session_db.query(Device).filter_by(device_id=device, key=key).first()
        if device_exists:
            session_db.close()
            return jsonify({"success": False, "status": "DEVICE_EXISTS", "message": "Device already registered"}), 400

        device_count = session_db.query(Device).filter_by(key=key).count()
        max_devices = db_key.device_limit

        if device_count >= max_devices:
            session_db.close()
            return jsonify({
                "success": False,
                "status": "DEVICE_LIMIT_REACHED",
                "message": f"Device limit reached (max {max_devices})",
                "device_limit": max_devices,
                "current_devices": device_count
            }), 400

        new_device = Device(device_id=device, key=key)
        session_db.add(new_device)
        session_db.commit()
        log_activity("DEVICE_ADDED_MANUAL", {"key": key, "device": device})

        return jsonify({
            "success": True,
            "status": "DEVICE_ADDED",
            "message": "Device added successfully",
            "key": key,
            "device": device,
            "device_limit": max_devices,
            "current_devices": device_count + 1,
            "devices_remaining": max_devices - (device_count + 1)
        })
    except Exception as e:
        print(f"❌ Add device error: {e}", file=sys.stderr)
        return jsonify({"success": False, "status": "ERROR", "message": str(e)}), 500
    finally:
        session_db.close()

@app.route('/api/key/devices', methods=['GET'])
def get_key_devices():
    try:
        key = sanitize_key(request.args.get('key'))
        if not key:
            return jsonify({"success": False, "status": "ERROR", "message": "Key required"}), 400

        session_db = SessionLocal()
        db_key = session_db.query(Key).filter_by(key=key).first()
        if not db_key:
            session_db.close()
            return jsonify({"success": False, "status": "INVALID", "message": "Invalid key"}), 400

        devices = session_db.query(Device).filter_by(key=key).all()
        device_list = [d.device_id for d in devices]

        return jsonify({
            "success": True,
            "key": key,
            "device_limit": db_key.device_limit,
            "current_devices": len(devices),
            "devices": device_list,
            "devices_remaining": db_key.device_limit - len(devices)
        })
    except Exception as e:
        print(f"❌ Get devices error: {e}", file=sys.stderr)
        return jsonify({"success": False, "status": "ERROR", "message": str(e)}), 500
    finally:
        session_db.close()

@app.route('/api/stats', methods=['GET'])
def get_stats():
    try:
        session_db = SessionLocal()
        total_keys = session_db.query(Key).count()
        used_keys = session_db.query(Key).filter_by(used=True).count()
        active_keys = total_keys - used_keys
        expired_keys = session_db.query(Key).filter(Key.expires < datetime.now()).count()
        custom_keys = session_db.query(Key).filter_by(is_custom=True).count()
        total_devices = session_db.query(Device).count()

        return jsonify({
            "total_keys": total_keys,
            "used_keys": used_keys,
            "active_keys": active_keys,
            "expired_keys": expired_keys,
            "custom_keys": custom_keys,
            "total_devices": total_devices
        })
    except Exception as e:
        print(f"❌ Stats error: {e}", file=sys.stderr)
        return jsonify({"error": str(e)}), 400
    finally:
        session_db.close()

@app.route('/api/keys', methods=['GET'])
@admin_required
def list_keys():
    try:
        session_db = SessionLocal()
        keys = session_db.query(Key).all()
        devices = session_db.query(Device).all()

        result = []
        for k in keys:
            device_count = sum(1 for d in devices if d.key == k.key)
            status_display = "ACTIVE" if k.used and k.expires > datetime.now() else \
                             "EXPIRED" if k.expires < datetime.now() else \
                             "UNUSED"
            if k.is_custom:
                status_display += " ✏️"
            result.append({
                "key": k.key,
                "duration_type": k.duration_type,
                "duration_value": k.duration_value,
                "created": k.created.isoformat(),
                "expires": k.expires.isoformat(),
                "used": k.used,
                "activated": k.activated.isoformat() if k.activated else None,
                "status": k.status,
                "is_custom": k.is_custom,
                "device_limit": k.device_limit,
                "current_devices": device_count,
                "devices_remaining": k.device_limit - device_count,
                "status_display": status_display
            })
        return jsonify(result)
    except Exception as e:
        print(f"❌ List keys error: {e}", file=sys.stderr)
        return jsonify({"error": str(e)}), 400
    finally:
        session_db.close()

@app.route('/api/devices', methods=['GET'])
@admin_required
def list_devices():
    try:
        session_db = SessionLocal()
        devices = session_db.query(Device).all()
        result = [{"device_id": d.device_id, "key": d.key, "registered": d.registered.isoformat()} for d in devices]
        return jsonify(result)
    except Exception as e:
        print(f"❌ List devices error: {e}", file=sys.stderr)
        return jsonify({"error": str(e)}), 400
    finally:
        session_db.close()

@app.route('/api/activity', methods=['GET'])
@admin_required
def list_activity():
    try:
        session_db = SessionLocal()
        activities = session_db.query(Activity).order_by(Activity.timestamp.desc()).limit(50).all()
        result = [{"timestamp": a.timestamp.isoformat(), "action": a.action, "details": a.details} for a in activities]
        return jsonify(result)
    except Exception as e:
        print(f"❌ List activity error: {e}", file=sys.stderr)
        return jsonify({"error": str(e)}), 400
    finally:
        session_db.close()

@app.route('/api/delete/<key>', methods=['DELETE'])
@admin_required
def delete_key(key):
    try:
        clean_key = sanitize_key(key)
        session_db = SessionLocal()
        db_key = session_db.query(Key).filter_by(key=clean_key).first()
        if db_key:
            session_db.delete(db_key)
            session_db.query(Device).filter_by(key=clean_key).delete()
            session_db.commit()
            log_activity("DELETE", {"key": clean_key})
            return jsonify({"success": True, "message": "Key deleted"})
        return jsonify({"success": False, "error": "Key not found"}), 404
    except Exception as e:
        print(f"❌ Delete error: {e}", file=sys.stderr)
        return jsonify({"error": str(e)}), 400
    finally:
        session_db.close()

@app.route('/api/clear', methods=['DELETE'])
@admin_required
def clear_all():
    try:
        session_db = SessionLocal()
        session_db.query(Key).delete()
        session_db.query(Device).delete()
        session_db.query(Activity).delete()
        session_db.commit()
        log_activity("CLEAR_ALL", {})
        return jsonify({"success": True, "message": "All data cleared"})
    except Exception as e:
        print(f"❌ Clear error: {e}", file=sys.stderr)
        return jsonify({"error": str(e)}), 400
    finally:
        session_db.close()

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
# UI (unchanged – same as before)
# =============================================

HTML = '''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HEX KEY SYSTEM</title>
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
        .stat { background: #111; border: 1px solid #222; border-radius: 12px; padding: 20px; text-align: center; }
        .stat:hover { border-color: #00ff88; }
        .stat .num { font-size: 32px; font-weight: 900; color: #00ff88; }
        .stat .label { color: #666; font-size: 12px; text-transform: uppercase; margin-top: 5px; }
        .panel { background: #111; border: 1px solid #222; border-radius: 12px; padding: 25px; margin-bottom: 25px; }
        .panel h3 { color: #00ff88; margin-bottom: 15px; }
        .panel h3 i { margin-right: 10px; }
        .input-group { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
        .input-group input, .input-group select { padding: 10px 15px; background: #1a1a1a; border: 2px solid #222; border-radius: 8px; color: #fff; font-size: 14px; flex: 1; min-width: 80px; }
        .input-group input:focus, .input-group select:focus { outline: none; border-color: #00ff88; }
        .input-group textarea { padding: 10px 15px; background: #1a1a1a; border: 2px solid #222; border-radius: 8px; color: #fff; font-size: 13px; flex: 1; min-width: 200px; font-family: monospace; resize: vertical; }
        .btn { padding: 10px 25px; border: none; border-radius: 8px; font-weight: 700; cursor: pointer; transition: 0.3s; }
        .btn-primary { background: #00ff88; color: #0a0a0a; }
        .btn-primary:hover { transform: scale(1.05); }
        .btn-custom { background: #ffaa00; color: #0a0a0a; }
        .btn-custom:hover { transform: scale(1.05); }
        .btn-danger { background: #ff4444; color: #fff; }
        .btn-danger:hover { transform: scale(1.05); }
        .btn-sm { padding: 5px 12px; font-size: 11px; }
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
        .scrollable { max-height: 400px; overflow-y: auto; }
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
        <h1><i class="fas fa-crown"></i> HEX KEY SYSTEM</h1>
        <span class="badge"><i class="fas fa-shield-alt"></i> SECURE</span>
    </div>
    <div class="container">
        <div class="stats" id="stats">
            <div class="stat"><div class="num" id="totalKeys">0</div><div class="label">Total Keys</div></div>
            <div class="stat"><div class="num" id="activeKeys">0</div><div class="label">Active Keys</div></div>
            <div class="stat"><div class="num" id="usedKeys">0</div><div class="label">Used Keys</div></div>
            <div class="stat"><div class="num" id="expiredKeys">0</div><div class="label">Expired Keys</div></div>
            <div class="stat"><div class="num" id="totalDevices">0</div><div class="label">Devices</div></div>
        </div>

        <div class="panel">
            <h3><i class="fas fa-robot"></i> Generate Keys</h3>
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
            <h3><i class="fas fa-pen"></i> Custom Keys</h3>
            <div class="input-group">
                <textarea id="customKeysText" rows="3" placeholder="MYKEY123&#10;VIPKEY456" style="flex:2;"></textarea>
                <div style="display:flex; flex-direction:column; gap:8px; flex:1; min-width:150px;">
                    <div style="display:flex; gap:8px; flex-wrap:wrap;">
                        <input type="number" id="customDurationValue" value="24" min="1" max="9999" style="flex:1; min-width:60px;">
                        <select id="customDurationType" style="flex:1; min-width:80px;">
                            <option value="hours">Hours</option>
                            <option value="days">Days</option>
                        </select>
                        <input type="number" id="customDeviceLimit" value="1" min="1" max="10" style="flex:1; min-width:60px;" placeholder="Devices">
                    </div>
                    <button class="btn btn-custom" onclick="generateCustomKeys()"><i class="fas fa-plus"></i> Add Keys</button>
                </div>
            </div>
            <div id="customGeneratedKeys"></div>
        </div>

        <div class="panel">
            <div class="tabs">
                <div class="tab active" onclick="switchTab('keys')"><i class="fas fa-keys"></i> Keys</div>
                <div class="tab" onclick="switchTab('devices')"><i class="fas fa-laptop"></i> Devices</div>
                <div class="tab" onclick="switchTab('api')"><i class="fas fa-code"></i> API</div>
                <div class="tab" onclick="switchTab('activity')"><i class="fas fa-history"></i> Activity</div>
            </div>
            <div id="tabKeys" class="tab-content active">
                <div class="scrollable">
                    <table>
                        <thead><tr><th>Key</th><th>Duration</th><th>Devices</th><th>Status</th><th>Expires</th><th>Action</th></tr></thead>
                        <tbody id="keysTable"></tbody>
                    </table>
                </div>
            </div>
            <div id="tabDevices" class="tab-content">
                <div class="scrollable">
                    <table>
                        <thead><tr><th>Device ID</th><th>Key</th><th>Registered</th></tr></thead>
                        <tbody id="devicesTable"></tbody>
                    </table>
                </div>
            </div>
            <div id="tabApi" class="tab-content">
                <div style="background:#0a0a0a; padding:20px; border-radius:8px; border:1px solid #222;">
                    <h4 style="color:#00ff88;"><i class="fas fa-plug"></i> Java API - Simple & Secure</h4>
                    <div style="margin:15px 0; padding:15px; background:#000; border-radius:6px; font-family:monospace; font-size:13px; color:#aaa;">
                        <p><span style="color:#00ff88;">POST</span> /api/login - Login with key + device</p>
                        <p style="color:#666; font-size:12px; margin-left:20px;">Request: {"key":"KEY","device":"DEVICE_ID"}</p>
                        <p style="color:#666; font-size:12px; margin-left:20px;">Response: SUCCESS or error status</p>
                        <p style="margin-top:8px;"><span style="color:#ffaa00;">POST</span> /api/activate - Activate key + device</p>
                        <p style="margin-top:8px;"><span style="color:#00ff88;">GET</span> /api/check?key=KEY&device=DEVICE - Check status</p>
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
            <i class="fas fa-crown" style="color:#00ff88;"></i> HEX KEY SYSTEM &bull; 
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
            toast('Logged in', 'success');
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

function loadAll() { loadStats(); loadKeys(); loadDevices(); loadActivity(); }

function loadStats() {
    fetch('/api/stats')
    .then(res => res.json())
    .then(data => {
        document.getElementById('totalKeys').textContent = data.total_keys || 0;
        document.getElementById('activeKeys').textContent = data.active_keys || 0;
        document.getElementById('usedKeys').textContent = data.used_keys || 0;
        document.getElementById('expiredKeys').textContent = data.expired_keys || 0;
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
            tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:#444; padding:20px;">No keys</td></tr>';
            return;
        }
        data.forEach(k => {
            const status = k.status_display || 'UNKNOWN';
            let statusClass = 'status-inactive';
            if (status.includes('ACTIVE')) statusClass = 'status-active';
            else if (status.includes('EXPIRED')) statusClass = 'status-expired';
            else if (status.includes('USED')) statusClass = 'status-used';
            
            const durationDisplay = k.duration_type === 'days' 
                ? `<span class="duration-badge duration-days">${k.duration_value}d</span>`
                : `<span class="duration-badge duration-hours">${k.duration_value}h</span>`;
            
            const deviceDisplay = `${k.current_devices || 0}/${k.device_limit || 1}`;
            
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td style="font-family:monospace; font-size:12px;">${k.key} ${k.is_custom ? '<span class="custom-tag">✏️</span>' : ''}</td>
                <td>${durationDisplay}</td>
                <td>${deviceDisplay}</td>
                <td class="${statusClass}">${status}</td>
                <td style="font-size:11px;">${new Date(k.expires).toLocaleString()}</td>
                <td><button class="btn btn-danger btn-sm" onclick="deleteKey('${k.key}')"><i class="fas fa-trash"></i></button></td>
            `;
            tbody.appendChild(tr);
        });
    })
    .catch(() => console.log('Keys load error'));
}

function loadDevices() {
    fetch('/api/devices')
    .then(res => res.json())
    .then(data => {
        const tbody = document.getElementById('devicesTable');
        tbody.innerHTML = '';
        if (!data || data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="3" style="text-align:center; color:#444; padding:20px;">No devices</td></tr>';
            return;
        }
        data.forEach(d => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td style="font-family:monospace; font-size:10px;">${d.device_id}</td>
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
            tbody.innerHTML = '<tr><td colspan="3" style="text-align:center; color:#444; padding:20px;">No activity</td></tr>';
            return;
        }
        data.slice(-20).reverse().forEach(a => {
            const tr = document.createElement('tr');
            const details = typeof a.details === 'string' ? a.details : JSON.stringify(a.details);
            tr.innerHTML = `
                <td style="font-size:11px;">${new Date(a.timestamp).toLocaleString()}</td>
                <td><span style="color:#00ff88;">${a.action}</span></td>
                <td style="font-size:12px; color:#888;">${details}</td>
            `;
            tbody.appendChild(tr);
        });
    })
    .catch(() => console.log('Activity load error'));
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
            html += `<div style="width:100%; color:#888; font-size:12px;">Device limit: ${data.device_limit}</div>`;
            html += '</div>';
            document.getElementById('generatedKeys').innerHTML = html;
            toast('Generated ' + data.count + ' key(s)', 'success');
            loadAll();
        } else {
            toast('Failed: ' + (data.error || 'Unknown'), 'error');
        }
    })
    .catch(err => toast('Error: ' + err.message, 'error'));
}

function generateCustomKeys() {
    const keysText = document.getElementById('customKeysText').value;
    const durationValue = document.getElementById('customDurationValue').value || 24;
    const durationType = document.getElementById('customDurationType').value;
    const deviceLimit = document.getElementById('customDeviceLimit').value || 1;

    if (!keysText.trim()) {
        toast('Enter at least one key', 'error');
        return;
    }

    const keys = keysText.split('\\n').map(k => k.trim().toUpperCase()).filter(k => k);
    if (keys.length === 0) {
        toast('No valid keys', 'error');
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
                html += `<div class="key-display" style="border-color:#ffaa00;">${k} ✏️ <button class="copy-btn" onclick="copyKey('${k}')"><i class="fas fa-copy"></i></button></div>`;
            });
            if (data.duplicates && data.duplicates.length > 0) {
                html += `<div style="color:#ffaa00; font-size:12px;">⚠️ Duplicates: ${data.duplicates.join(', ')}</div>`;
            }
            html += `<div style="width:100%; color:#888; font-size:12px;">Device limit: ${data.device_limit}</div>`;
            html += '</div>';
            document.getElementById('customGeneratedKeys').innerHTML = html;
            document.getElementById('customKeysText').value = '';
            toast('Added ' + data.count + ' custom key(s)', 'success');
            loadAll();
        } else {
            toast('Failed: ' + (data.error || 'Unknown'), 'error');
        }
    })
    .catch(err => toast('Error: ' + err.message, 'error'));
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

function copyKey(key) { navigator.clipboard.writeText(key); toast('Copied!', 'success'); }

function switchTab(tab) {
    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.tab').forEach(el => el.classList.remove('active'));
    document.getElementById('tabKeys').classList.toggle('active', tab === 'keys');
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
</html>'''

@app.route('/')
def admin_panel():
    return render_template_string(HTML)

# =============================================
# RUN
# =============================================

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5005))
    app.run(host='0.0.0.0', port=port, debug=False)