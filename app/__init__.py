import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf import CSRFProtect
from config import Config
from flask_migrate import Migrate

csrf = CSRFProtect()
db = SQLAlchemy()
login_manager = LoginManager()
migrate = Migrate()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize extensions with the app
    db.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)     # ✅ CORRECT LOCATION

    # Flask-Login configuration
    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = 'info'
    login_manager.login_message = 'Please log in to access this page.'

    # --- Blueprint Registration ---
    from app.auth.routes import auth_bp
    app.register_blueprint(auth_bp)

    try:
        from app.jobs.routes import jobs_bp
        app.register_blueprint(jobs_bp)
    except ImportError:
        print("Warning: jobs blueprint not found.")

    try:
        from app.admin.routes import admin_bp
        app.register_blueprint(admin_bp)
    except ImportError:
        print("Warning: admin blueprint not found.")

    with app.app_context():
        from app import models

    return app
