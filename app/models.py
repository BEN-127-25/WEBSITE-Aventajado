from app import db, login_manager
from flask_login import UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

# ==========================================================
# USER MODEL
# ==========================================================
class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=True)
    password_hash = db.Column(db.String(200), nullable=False)

    # user roles: admin, employer, applicant
    role = db.Column(db.String(20), nullable=False, default="applicant")

    banned = db.Column(db.Boolean, default=False)

    resume_filename = db.Column(db.String(300))
    email_confirmed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # User approval status: 'pending', 'approved', 'rejected'
    status = db.Column(db.String(20), default="pending") 
    
    profile_picture = db.Column(db.String(300))
    
    # --- ADDED: Fields required by profile route in auth/routes.py ---
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    # -----------------------------------------------------------------

    # Relationships
    jobs = db.relationship("Job", backref="user", lazy=True)
    applications = db.relationship("JobApplication", backref="user", lazy=True)
    applicant_posts = db.relationship("ApplicantPost", backref="user", lazy=True)
    posts = db.relationship("Post", backref="user", cascade="all, delete-orphan")

    # --------------------------
    # Password Hashing Methods (CRITICAL for login and registration)
    # --------------------------
    @property
    def password(self):
        """Prevent password from being accessed directly"""
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        """Set password to a hashed value"""
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        """Check the hashed password against a plain password"""
        return check_password_hash(self.password_hash, password)

    # --------------------------
    # Helper Methods
    # --------------------------
    def is_admin(self):
        return self.role == "admin"

    def get_id(self):
        return str(self.id)

    def __repr__(self):
        return f"<User {self.username}>"


@login_manager.user_loader
def load_user(user_id):
    """Callback function for Flask-Login to load a user from the database."""
    return User.query.get(int(user_id))


# ==========================================================
# JOB MODEL
# ==========================================================
class Job(db.Model):
    __tablename__ = "jobs"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    # who created the job (employer/applicant)
    role = db.Column(db.String(20), nullable=False)

    title = db.Column(db.String(200), nullable=False)
    company = db.Column(db.String(200))
    description = db.Column(db.Text, nullable=False)

    experience_required = db.Column(db.String(200))
    degree_required = db.Column(db.String(200))

    resume_file = db.Column(db.String(200))

    date_posted = db.Column(db.DateTime, default=datetime.utcnow)

    # NEW — job status
    status = db.Column(db.String(20), default="open") 
    # open, pending, taken

    # NEW — relationship to applicants
    applications = db.relationship(
        "JobApplication",
        backref="job",
        lazy=True,
        cascade="all, delete-orphan"
    )


# ==========================================================
# JOB APPLICATION MODEL
# ==========================================================
class JobApplication(db.Model):
    __tablename__ = "job_applications"

    id = db.Column(db.Integer, primary_key=True)

    job_id = db.Column(db.Integer, db.ForeignKey("jobs.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    experience = db.Column(db.Text)
    resume_file = db.Column(db.String(255))

    status = db.Column(db.String(20), default="pending")
    # pending, approved, taken

    date_applied = db.Column(db.DateTime, default=datetime.utcnow)


# ==========================================================
# REGULAR POSTS
# ==========================================================
class Post(db.Model):
    __tablename__ = "posts"

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)

    experience = db.Column(db.String(200))
    degree = db.Column(db.String(200))
    desired_job = db.Column(db.String(200))
    resume_filename = db.Column(db.String(300))

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)


# ==========================================================
# APPLICANT PROFILE POSTS
# ==========================================================
class ApplicantPost(db.Model):
    __tablename__ = "applicant_posts"

    id = db.Column(db.Integer, primary_key=True)
    looking_for = db.Column(db.String(200), nullable=False)
    experience = db.Column(db.Text, nullable=False)
    resume_file = db.Column(db.String(255))
    
    # Description column ensures compatibility across different application components
    description = db.Column(db.Text, nullable=True) 

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)