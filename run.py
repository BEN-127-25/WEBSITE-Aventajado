from app import create_app, db
from flask_migrate import Migrate
import os

app = create_app()
migrate = Migrate(app, db)

# ----------------------------------------------------
# AUTO-CREATE DATABASE & TABLES ON FIRST RUN
# ----------------------------------------------------
with app.app_context():
    db_path = app.config["SQLALCHEMY_DATABASE_URI"].replace("sqlite:///", "")

    # If database file does not exist → create tables
    if not os.path.exists(db_path):
        print("📌 Database not found. Creating new database...")
        db.create_all()
        print("✅ Database created:", db_path)
    else:
        # Optional: ensure tables exist even if DB existed before
        db.create_all()
        print("✔ Tables verified")

if __name__ == "__main__":
    app.run(debug=True)
