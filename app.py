"""
app.py — HyperTrust Flask Application Entry Point
==================================================
ABE-Based Smart Network Access Control for Campus Network Resources
"""
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from flask import Flask, render_template
from config import Config
from db import get_db, close_db, init_db


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    app.config["DATABASE"] = Config.DB_PATH

    # Register DB teardown
    app.teardown_appcontext(close_db)

    # Initialize database schema on first run
    init_db(app)
    
    # Bootstrap ABE system keys & admin user automatically
    # Crucial for Vercel where the /tmp filesystem wipes on cold starts
    import init_db as full_init
    full_init.run()

    # ── Blueprints ────────────────────────────────────────────────────────────
    from routes.auth  import auth_bp
    from routes.admin import admin_bp
    from routes.user  import user_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(user_bp)

    # ── Error handlers ────────────────────────────────────────────────────────
    @app.errorhandler(403)
    def forbidden(e):
        return render_template("errors/403.html"), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def server_error(e):
        return render_template("errors/500.html"), 500

# Vercel requires the app variable to be exposed globally
app = create_app()

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
