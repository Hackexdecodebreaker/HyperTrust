"""
config.py — Application configuration
"""

import os
import secrets

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
    
    # Check if the execution directory is writable (Vercel is read-only)
    base_dir = os.path.abspath(os.path.dirname(__file__))
    if os.access(base_dir, os.W_OK):
        DB_PATH = os.path.join(base_dir, "instance", "hypertrust.db")
    else:
        DB_PATH = "/tmp/hypertrust.db"
        
    ADMIN_USERNAME = "admin"
    ADMIN_PASSWORD = "admin123"
    ADMIN_NAME = "System Administrator"
    DEBUG = True
