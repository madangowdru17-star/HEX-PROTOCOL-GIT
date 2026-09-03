# HEX KEY SYSTEM

A secure key management system with PostgreSQL persistence and device-based authentication.

## Features

- **Key Management**: Generate and manage unique keys with customizable durations
- **Device Authentication**: Register and authenticate devices with IP tracking
- **Device Limit**: Enforce per-key device limits (1-10 devices)
- **Admin Panel**: Modern web interface for key and device management
- **API Endpoints**: RESTful API for Java application integration
- **Activity Logging**: Track all system actions
- **Railway Compatible**: Deploy to Railway with PostgreSQL

## API Endpoints

### Public Endpoints
- `POST /api/login` - Login with key + device
- `POST /api/activate` - Activate a key
- `GET /api/check` - Check key status
- `POST /api/device/check` - Check if device is registered
- `GET /api/stats` - Get system statistics

### Admin Endpoints (Requires Authentication)
- `POST /api/generate` - Generate keys
- `POST /api/generate/custom` - Generate custom keys
- `GET /api/keys` - List all keys
- `GET /api/devices` - List all devices
- `GET /api/activity` - View activity log
- `DELETE /api/delete/<key>` - Delete a key
- `DELETE /api/clear` - Clear all data

## Admin Credentials
- Password: `HEX444`

## Deployment

### Railway
1. Create a PostgreSQL database in Railway
2. Set `DATABASE_URL` environment variable
3. Deploy with the provided `railway.json`

### Local Development
```bash
pip install -r requirements.txt
export DATABASE_URL=sqlite:///keys.db
python app.py