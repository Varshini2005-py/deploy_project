import os
from dotenv import load_dotenv

# load_dotenv only fills values NOT already set in environment
# So Render env vars always take priority over .env file
load_dotenv(override=False)

# MongoDB Configuration
MONGO_URI = os.environ.get("MONGO_URI") or "mongodb://localhost:27017/"
DB_NAME   = os.environ.get("DB_NAME", "xai_itd_dlp")

# Debug print — visible in Render logs
_uri_preview = MONGO_URI[:40] + "..." if len(MONGO_URI) > 40 else MONGO_URI
print(f"[CONFIG] MONGO_URI: {_uri_preview}")
print(f"[CONFIG] DB_NAME: {DB_NAME}")
print(f"[CONFIG] FLASK_ENV: {os.environ.get('FLASK_ENV','development')}")

# SMTP Configuration
SMTP_SERVER   = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT     = int(os.environ.get("SMTP_PORT", 587))
SMTP_EMAIL    = os.environ.get("SMTP_EMAIL", "your_email@gmail.com")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "your_app_password")

# App Config
SECRET_KEY         = os.environ.get("SECRET_KEY", "xai-itd-dlp-secret-2025")
OTP_EXPIRY_SECONDS = 120

# Environment
FLASK_ENV     = os.environ.get("FLASK_ENV", "development")
IS_PRODUCTION = FLASK_ENV == "production"

# OTP redirect email
OTP_REDIRECT_EMAIL = os.environ.get("OTP_REDIRECT_EMAIL", SMTP_EMAIL)