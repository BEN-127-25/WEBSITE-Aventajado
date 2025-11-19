import os
import secrets
from werkzeug.utils import secure_filename
from flask import current_app
from itsdangerous import URLSafeTimedSerializer

def allowed_file(filename):
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in current_app.config['ALLOWED_EXTENSIONS']

def save_resume(file):
    """Save uploaded resume securely and return its filename."""
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(file.filename)
    resume_filename = random_hex + f_ext
    resume_path = os.path.join(current_app.root_path, 'static/uploads', resume_filename)
    file.save(resume_path)
    return resume_filename

def generate_confirmation_token(secret_key, email):
    s = URLSafeTimedSerializer(secret_key)
    return s.dumps(email, salt='email-confirm-salt')

def confirm_token(secret_key, token, expiration=3600):
    s = URLSafeTimedSerializer(secret_key)
    try:
        email = s.loads(token, salt='email-confirm-salt', max_age=expiration)
    except Exception:
        return None
    return email
