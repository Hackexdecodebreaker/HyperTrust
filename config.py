"""
config.py — Application configuration
"""

import os
import secrets

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
    
    # On Vercel, the only writable directory is /tmp
    if os.environ.get("VERCEL"):
        DB_PATH = "/tmp/hypertrust.db"
    else:
        DB_PATH = os.path.join(os.path.dirname(__file__), "instance", "hypertrust.db")
        
    ADMIN_USERNAME = "admin"
    ADMIN_PASSWORD = "admin123"
    ADMIN_NAME = "System Administrator"
    DEBUG = True
