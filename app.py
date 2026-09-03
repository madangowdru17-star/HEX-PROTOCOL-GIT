# app.py - Premium HEX Cheats GitXOS System
import os
import json
import hashlib
import secrets
import string
import re
import sys
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template, session
from flask_cors import CORS
from functools import wraps
from sqlalchemy import create_engine, Column, String, Boolean, DateTime, Integer, JSON, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import func

app = Flask(__name__)
app.secret_key = "HEX_CHEATS_GITXOS_SUPREME_2026"
CORS(app)

# =============================================
# DATABASE SETUP
# =============================================

DATABASE_URL = os.environ.get('DATABASE_URL')
if not DATABASE_URL:
    print("ERROR: DATABASE_URL environment variable not set!", file=sys.stderr)
    DATABASE_URL = 'sqlite:///keys.db'
    print("Using SQLite fallback", file=sys.stderr)

print(f"Connecting to database: {DATABASE_URL[:30]}...")

try:
    engine = create_engine(DATABASE_URL)
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
    print("Database connection successful!")
except Exception as e:
    print(f"Database connection failed: {e}", file=sys.stderr)
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
    ip_restriction = Column(String(45), nullable=True)
    key_type = Column(String(20), default='STANDARD')
    generated_by = Column(String(50), default='SYSTEM')

class Device(Base):
    __tablename__ = 'devices'
    id = Column(Integer, primary_key=True)
    device_id = Column(String(64), nullable=False)
    key = Column(String(32), nullable=False)
    registered = Column(DateTime, default=func.now())
    ip_address = Column(String(45), nullable=True)
    last_activity = Column(DateTime, default=func.now())
    user_agent = Column(String(255), nullable=True)

class Activity(Base):
    __tablename__ = 'activity'
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=func.now())
    action = Column(String(50))
    details = Column(JSON)

# Create tables
Base.metadata.create_all(engine)
print("Tables ready.")

# =============================================
# HELPERS
# =============================================

def sanitize_key(key):
    if not key:
        return None
    return re.sub(r'[^A-Z0-9-]', '', key.upper().strip())

def generate_key():
    chars = string.ascii_uppercase + string.digits
    return ''.join(secrets.choice(chars) for _ in range(16))

def generate_hex_key():
    """Generate HEX-XXXX-XXXX format key"""
    part1 = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4))
    part2 = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4))
    part3 = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4))
    return f"HEX-{part1}-{part2}-{part3}"

def generate_5hour_key():
    """Generate 5-hour key with HEX-XXXX-XXXX format"""
    return generate_hex_key()

def get_device_id(request):
    user_agent = request.headers.get('User-Agent', 'unknown')
    ip = request.remote_addr
    combined = f"{user_agent}|{ip}"
    return hashlib.sha256(combined.encode()).hexdigest()[:32]

def get_client_ip(request):
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr

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
        print(f"Failed to log activity: {e}", file=sys.stderr)
    finally:
        session_db.close()

# =============================================
# API ENDPOINTS
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

@app.route('/api/login', methods=['POST'])
def login_key():
    try:
        data = request.json
        key = sanitize_key(data.get('key'))
        device = data.get('device_id') or data.get('device') or get_device_id(request)
        ip = get_client_ip(request)
        user_agent = request.headers.get('User-Agent', 'unknown')

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
            return jsonify({"success": False, "status": "INACTIVE", "message": "Key not activated"}), 400

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
            device_exists.last_activity = datetime.now()
            device_exists.user_agent = user_agent
            session_db.commit()
            log_activity("LOGIN_SUCCESS", {"key": key, "device": device, "ip": ip})
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
                "duration_value": db_key.duration_value,
                "already_registered": True,
                "key_type": db_key.key_type
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

            new_device = Device(device_id=device, key=key, ip_address=ip, last_activity=datetime.now(), user_agent=user_agent)
            session_db.add(new_device)
            session_db.commit()
            log_activity("DEVICE_AUTO_REGISTER", {"key": key, "device": device, "ip": ip})

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
                "devices_remaining": max_devices - (device_count + 1),
                "already_registered": False,
                "key_type": db_key.key_type
            })
    except Exception as e:
        print(f"Login error: {e}", file=sys.stderr)
        return jsonify({"success": False, "status": "ERROR", "message": str(e)}), 500
    finally:
        session_db.close()

@app.route('/api/activate', methods=['POST'])
def activate_key():
    try:
        data = request.json
        key = sanitize_key(data.get('key'))
        device = data.get('device_id') or data.get('device') or get_device_id(request)
        ip = get_client_ip(request)

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
        db_key.ip_restriction = ip

        new_device = Device(device_id=device, key=key, ip_address=ip, last_activity=datetime.now())
        session_db.add(new_device)
        session_db.commit()

        log_activity("KEY_ACTIVATED", {"key": key, "device": device, "ip": ip})

        return jsonify({
            "success": True,
            "status": "ACTIVATED",
            "message": "Key activated successfully",
            "key": key,
            "device": device,
            "expires": db_key.expires.isoformat(),
            "device_limit": db_key.device_limit,
            "key_type": db_key.key_type
        })
    except Exception as e:
        print(f"Activate error: {e}", file=sys.stderr)
        return jsonify({"success": False, "status": "ERROR", "message": str(e)}), 500
    finally:
        session_db.close()

@app.route('/api/check', methods=['GET'])
def check_key():
    try:
        key = sanitize_key(request.args.get('key'))
        device = request.args.get('device_id') or request.args.get('device')

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
            "devices_remaining": db_key.device_limit - device_count,
            "key_type": db_key.key_type
        })
    except Exception as e:
        print(f"Check error: {e}", file=sys.stderr)
        return jsonify({"success": False, "status": "ERROR", "message": str(e)}), 500
    finally:
        session_db.close()

# =============================================
# DEVICE CHECK API
# =============================================

@app.route('/api/device/check', methods=['POST'])
def check_device():
    try:
        data = request.json
        device_id = data.get('device_id')
        
        if not device_id:
            return jsonify({
                "success": False,
                "error": "Device ID required"
            }), 400

        session_db = SessionLocal()
        device = session_db.query(Device).filter_by(device_id=device_id).first()
        
        if device:
            db_key = session_db.query(Key).filter_by(key=device.key).first()
            is_valid = db_key and db_key.used and db_key.expires > datetime.now()
            
            return jsonify({
                "success": True,
                "registered": True,
                "status": "REGISTERED",
                "message": "Device already registered",
                "key": device.key,
                "registered_at": device.registered.isoformat(),
                "last_activity": device.last_activity.isoformat() if device.last_activity else None,
                "is_key_valid": is_valid,
                "key_type": db_key.key_type if db_key else "UNKNOWN"
            })
        else:
            return jsonify({
                "success": True,
                "registered": False,
                "status": "NOT_REGISTERED",
                "message": "Device not registered"
            })
    except Exception as e:
        print(f"Device check error: {e}", file=sys.stderr)
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        session_db.close()

# =============================================
# GENERATE 5-HOUR KEY API
# =============================================

@app.route('/api/generate/5hour', methods=['POST'])
def generate_5hour_key_api():
    try:
        data = request.json
        count = int(data.get('count', 1))
        
        session_db = SessionLocal()
        generated = []
        
        for _ in range(count):
            key = generate_5hour_key()
            expires = datetime.now() + timedelta(hours=5)
            
            new_key = Key(
                key=key,
                duration_type='hours',
                duration_value=5,
                expires=expires,
                used=False,
                status='ACTIVE',
                device_limit=1,
                key_type='5HOUR',
                generated_by='API_5HOUR'
            )
            session_db.add(new_key)
            generated.append(key)
        
        session_db.commit()
        log_activity("GENERATE_5HOUR", {"count": count, "keys": generated})
        
        return jsonify({
            "success": True,
            "keys": generated,
            "count": count,
            "duration_type": "hours",
            "duration_value": 5,
            "key_type": "5HOUR",
            "format": "HEX-XXXX-XXXX"
        })
    except Exception as e:
        print(f"Generate 5-hour error: {e}", file=sys.stderr)
        return jsonify({"success": False, "error": str(e)}), 400
    finally:
        session_db.close()

# =============================================
# CUSTOM KEY GENERATION (Any Format)
# =============================================

@app.route('/api/generate/custom/any', methods=['POST'])
@admin_required
def generate_custom_any_key():
    try:
        data = request.json
        custom_keys = data.get('keys', [])
        duration_type = data.get('duration_type', 'hours')
        duration_value = int(data.get('duration_value', 24))
        device_limit = int(data.get('device_limit', 1))
        key_type = data.get('key_type', 'CUSTOM')

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
                device_limit=device_limit,
                key_type=key_type,
                generated_by="ADMIN"
            )
            session_db.add(new_key)
            generated.append(clean_key)

        session_db.commit()
        log_activity("GENERATE_CUSTOM_ANY", {"count": len(generated), "duplicates": len(duplicates), "type": key_type})

        return jsonify({
            "success": True,
            "keys": generated,
            "duplicates": duplicates,
            "count": len(generated),
            "duration_type": duration_type,
            "duration_value": duration_value,
            "device_limit": device_limit,
            "key_type": key_type
        })
    except Exception as e:
        print(f"Generate custom any error: {e}", file=sys.stderr)
        return jsonify({"success": False, "error": str(e)}), 400
    finally:
        session_db.close()

# =============================================
# GENERATE & ADMIN ENDPOINTS
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
        key_type = data.get('key_type', 'STANDARD')

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
                device_limit=device_limit,
                key_type=key_type,
                generated_by="ADMIN"
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
            "device_limit": device_limit,
            "key_type": key_type
        })
    except Exception as e:
        print(f"Generate error: {e}", file=sys.stderr)
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
        key_type = data.get('key_type', 'CUSTOM')

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
                device_limit=device_limit,
                key_type=key_type,
                generated_by="ADMIN"
            )
            session_db.add(new_key)
            generated.append(clean_key)

        session_db.commit()
        log_activity("GENERATE_CUSTOM", {"count": len(generated), "duplicates": len(duplicates), "type": key_type})

        return jsonify({
            "success": True,
            "keys": generated,
            "duplicates": duplicates,
            "count": len(generated),
            "duration_type": duration_type,
            "duration_value": duration_value,
            "device_limit": device_limit,
            "key_type": key_type
        })
    except Exception as e:
        print(f"Generate custom error: {e}", file=sys.stderr)
        return jsonify({"success": False, "error": str(e)}), 400
    finally:
        session_db.close()

@app.route('/api/add/device', methods=['POST'])
def add_device():
    try:
        data = request.json
        key = sanitize_key(data.get('key'))
        device = data.get('device_id') or data.get('device') or get_device_id(request)
        ip = get_client_ip(request)

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

        new_device = Device(device_id=device, key=key, ip_address=ip, last_activity=datetime.now())
        session_db.add(new_device)
        session_db.commit()
        log_activity("DEVICE_ADDED_MANUAL", {"key": key, "device": device, "ip": ip})

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
        print(f"Add device error: {e}", file=sys.stderr)
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
        device_list = [{
            "device_id": d.device_id,
            "ip_address": d.ip_address,
            "registered": d.registered.isoformat(),
            "last_activity": d.last_activity.isoformat() if d.last_activity else None
        } for d in devices]

        return jsonify({
            "success": True,
            "key": key,
            "device_limit": db_key.device_limit,
            "current_devices": len(devices),
            "devices": device_list,
            "devices_remaining": db_key.device_limit - len(devices)
        })
    except Exception as e:
        print(f"Get devices error: {e}", file=sys.stderr)
        return jsonify({"success": False, "status": "ERROR", "message": str(e)}), 500
    finally:
        session_db.close()

@app.route('/api/stats', methods=['GET'])
def get_stats():
    try:
        session_db = SessionLocal()
        total_keys = session_db.query(Key).count()
        used_keys = session_db.query(Key).filter_by(used=True).count()
        active_keys = session_db.query(Key).filter(Key.used == True, Key.expires > datetime.now()).count()
        expired_keys = session_db.query(Key).filter(Key.expires < datetime.now()).count()
        custom_keys = session_db.query(Key).filter_by(is_custom=True).count()
        total_devices = session_db.query(Device).count()
        unique_ips = session_db.query(Device.ip_address).distinct().count()
        
        # Key type stats
        key_types = session_db.query(Key.key_type, func.count(Key.key_type)).group_by(Key.key_type).all()
        key_type_stats = {kt[0]: kt[1] for kt in key_types}

        return jsonify({
            "total_keys": total_keys,
            "used_keys": used_keys,
            "active_keys": active_keys,
            "expired_keys": expired_keys,
            "custom_keys": custom_keys,
            "total_devices": total_devices,
            "unique_ips": unique_ips,
            "key_types": key_type_stats
        })
    except Exception as e:
        print(f"Stats error: {e}", file=sys.stderr)
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
                status_display += " CUSTOM"
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
                "status_display": status_display,
                "ip_restriction": k.ip_restriction,
                "key_type": k.key_type,
                "generated_by": k.generated_by
            })
        return jsonify(result)
    except Exception as e:
        print(f"List keys error: {e}", file=sys.stderr)
        return jsonify({"error": str(e)}), 400
    finally:
        session_db.close()

@app.route('/api/devices', methods=['GET'])
@admin_required
def list_devices():
    try:
        session_db = SessionLocal()
        devices = session_db.query(Device).all()
        result = [{
            "device_id": d.device_id, 
            "key": d.key, 
            "registered": d.registered.isoformat(),
            "ip_address": d.ip_address,
            "last_activity": d.last_activity.isoformat() if d.last_activity else None,
            "user_agent": d.user_agent
        } for d in devices]
        return jsonify(result)
    except Exception as e:
        print(f"List devices error: {e}", file=sys.stderr)
        return jsonify({"error": str(e)}), 400
    finally:
        session_db.close()

@app.route('/api/activity', methods=['GET'])
@admin_required
def list_activity():
    try:
        session_db = SessionLocal()
        activities = session_db.query(Activity).order_by(Activity.timestamp.desc()).limit(100).all()
        result = [{"timestamp": a.timestamp.isoformat(), "action": a.action, "details": a.details} for a in activities]
        return jsonify(result)
    except Exception as e:
        print(f"List activity error: {e}", file=sys.stderr)
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
        print(f"Delete error: {e}", file=sys.stderr)
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
        print(f"Clear error: {e}", file=sys.stderr)
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
        if data.get('password') == 'HEX444':
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
# UI ROUTES
# =============================================

@app.route('/')
def admin_panel():
    return render_template('admin_login.html')

@app.route('/dashboard')
def dashboard():
    if not session.get('admin'):
        return render_template('admin_login.html')
    return render_template('admin_dashboard.html')

@app.route('/keys')
def keys_page():
    if not session.get('admin'):
        return render_template('admin_login.html')
    return render_template('admin_keys.html')

@app.route('/devices')
def devices_page():
    if not session.get('admin'):
        return render_template('admin_login.html')
    return render_template('admin_devices.html')

@app.route('/api-status')
def api_status_page():
    if not session.get('admin'):
        return render_template('admin_login.html')
    return render_template('admin_api_status.html')

# =============================================
# RUN
# =============================================

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5005))
    app.run(host='0.0.0.0', port=port, debug=False)