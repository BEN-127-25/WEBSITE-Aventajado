# app.py
import os
from datetime import datetime
from flask import (
    Flask, render_template, request, redirect, url_for, flash, abort
)
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import (
    LoginManager, login_user, logout_user, login_required, current_user, UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash

# -----------------------
# Basic config
# -----------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "hirehub.db")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("HIREHUB_SECRET") or "dev-secret-change-me"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + DB_PATH
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = os.path.join(BASE_DIR, "static", "uploads")
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# -----------------------
# Extensions
# -----------------------
db = SQLAlchemy(app)
migrate = Migrate(app, db)  # optional; you can use migrations later
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "warning"

# -----------------------
# Models (adapted from your models.py)
# -----------------------
class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=True)
    password_hash = db.Column(db.String(200), nullable=False)

    # roles: admin, employer, applicant, employee, recruiter
    role = db.Column(db.String(20), nullable=False, default="applicant")
    banned = db.Column(db.Boolean, default=False)

    resume_filename = db.Column(db.String(300))
    email_confirmed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # User approval status: 'pending', 'approved', 'rejected'
    status = db.Column(db.String(20), default="pending")

    profile_picture = db.Column(db.String(300))
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))

    # relationships
    jobs = db.relationship("Job", backref="user", lazy=True, cascade="all, delete-orphan")
    applications = db.relationship("JobApplication", backref="user", lazy=True, cascade="all, delete-orphan")
    applicant_posts = db.relationship("ApplicantPost", backref="user", lazy=True, cascade="all, delete-orphan")
    posts = db.relationship("Post", backref="user", lazy=True, cascade="all, delete-orphan")

    @property
    def password(self):
        raise AttributeError("password is not a readable attribute")

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_admin(self):
        return self.role == "admin"

    def get_id(self):
        return str(self.id)

    def __repr__(self):
        return f"<User {self.username}>"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


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
    status = db.Column(db.String(20), default="open")  # open, pending, taken

    applications = db.relationship(
        "JobApplication",
        backref="job",
        lazy=True,
        cascade="all, delete-orphan"
    )


class JobApplication(db.Model):
    __tablename__ = "job_applications"

    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey("jobs.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    experience = db.Column(db.Text)
    resume_file = db.Column(db.String(255))
    status = db.Column(db.String(20), default="pending")  # pending, approved, taken
    date_applied = db.Column(db.DateTime, default=datetime.utcnow)


class Post(db.Model):
    __tablename__ = "posts"

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    experience = db.Column(db.String(200))
    degree = db.Column(db.String(200))
    desired_job = db.Column(db.String(200))
    resume_filename = db.Column(db.String(300))
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)


class ApplicantPost(db.Model):
    __tablename__ = "applicant_posts"

    id = db.Column(db.Integer, primary_key=True)
    looking_for = db.Column(db.String(200), nullable=False)
    experience = db.Column(db.Text, nullable=False)
    resume_file = db.Column(db.String(255))
    description = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)


# -----------------------
# Create DB (fallback if you haven't run migrations yet)
# -----------------------
# NOTE: In production you should use Flask-Migrate:
#   flask db init
#   flask db migrate -m "initial"
#   flask db upgrade
#
# For quick local startup we call create_all() if the file doesn't exist.
if not os.path.exists(DB_PATH):
    with app.app_context():
        db.create_all()
        print("Created database:", DB_PATH)


# -----------------------
# Helpers & decorators (role check using current_user)
# -----------------------
def roles_required(*roles):
    def decorator(f):
        from functools import wraps

        @wraps(f)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                flash("Please log in first.", "warning")
                return redirect(url_for("login"))

            if current_user.role not in roles:
                flash("You do not have permission to access that page.", "danger")
                # Redirect admin to admin page, others to posts
                if current_user.is_admin():
                    return redirect(url_for("admin_users"))
                return redirect(url_for("posts"))
            return f(*args, **kwargs)
        return wrapped
    return decorator


# -----------------------
# Routes
# -----------------------
@app.route("/")
def home():
    if current_user.is_authenticated:
        if current_user.is_admin():
            return redirect(url_for("admin_users"))
        return redirect(url_for("posts"))
    return render_template("home.html")


# ---------------------- Auth ----------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "applicant")

        if role not in ("admin", "employee", "recruiter", "applicant"):
            flash("Invalid role selected.", "danger")
            return redirect(url_for("register"))

        if not username or not password:
            flash("Username and password required.", "warning")
            return redirect(url_for("register"))

        if User.query.filter_by(username=username).first():
            flash("Username already exists.", "danger")
            return redirect(url_for("register"))

        user = User(username=username, role=role)
        user.password = password  # hashes via setter

        # If role is admin and no admin exists, auto-approve
        if role == "admin" and User.query.filter_by(role="admin").first() is None:
            user.status = "approved"

        db.session.add(user)
        db.session.commit()

        login_user(user)
        flash("Registration successful.", "success")

        if user.role in ("employee", "recruiter", "applicant"):
            return redirect(url_for("posts"))
        return redirect(url_for("admin_users"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()
        if not user or not user.verify_password(password):
            flash("Invalid username or password.", "danger")
            return redirect(url_for("login"))

        if user.banned:
            flash("Your account is banned.", "danger")
            return redirect(url_for("login"))

        login_user(user)
        flash("Logged in successfully.", "success")

        if user.is_admin():
            return redirect(url_for("admin_users"))
        return redirect(url_for("posts"))

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "info")
    return redirect(url_for("home"))


# ---------------------- Posts (jobs) ----------------------
@app.route("/posts")
@login_required
@roles_required("employee", "recruiter", "admin", "applicant")
def posts():
    jobs = Job.query.order_by(Job.id.desc()).all()
    return render_template("posts.html", jobs=jobs)


@app.route("/post/create", methods=["GET", "POST"])
@login_required
@roles_required("employee", "recruiter")
def create_post():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        company = request.form.get("company", "").strip()
        description = request.form.get("description", "").strip()

        if not title or not company or not description:
            flash("All fields are required.", "warning")
            return redirect(url_for("create_post"))

        job = Job(
            user_id=current_user.id,
            role=current_user.role,
            title=title,
            company=company,
            description=description
        )
        db.session.add(job)
        db.session.commit()
        flash("Job posted successfully.", "success")
        return redirect(url_for("posts"))

    return render_template("create_edit_post.html", action="Create")


@app.route("/post/edit/<int:post_id>", methods=["GET", "POST"])
@login_required
@roles_required("employee", "recruiter", "admin")
def edit_post(post_id):
    job = Job.query.get_or_404(post_id)

    if not (current_user.is_admin() or job.user_id == current_user.id):
        flash("You are not allowed to edit this post.", "danger")
        return redirect(url_for("posts"))

    if request.method == "POST":
        job.title = request.form.get("title", job.title)
        job.company = request.form.get("company", job.company)
        job.description = request.form.get("description", job.description)
        db.session.commit()
        flash("Post updated.", "success")
        return redirect(url_for("posts"))

    return render_template("create_edit_post.html", action="Edit", job=job)


@app.route("/post/delete/<int:post_id>", methods=["POST"])
@login_required
@roles_required("employee", "recruiter", "admin")
def delete_post(post_id):
    job = Job.query.get_or_404(post_id)

    if not (current_user.is_admin() or job.user_id == current_user.id):
        flash("You are not allowed to delete this.", "danger")
        return redirect(url_for("posts"))

    db.session.delete(job)
    db.session.commit()
    flash("Post deleted.", "success")
    return redirect(url_for("posts"))


# ---------------------- Admin ----------------------
@app.route("/admin/users")
@login_required
def admin_users():
    if not current_user.is_admin():
        flash("You must be an admin to view that page.", "danger")
        return redirect(url_for("posts"))

    users = User.query.order_by(User.id.asc()).all()
    return render_template("admin_users.html", users=users)


@app.route("/admin/ban/<int:user_id>", methods=["POST"])
@login_required
def ban_user(user_id):
    if not current_user.is_admin():
        flash("Not allowed", "danger")
        return redirect(url_for("posts"))

    if user_id == current_user.id:
        flash("You cannot ban yourself.", "warning")
        return redirect(url_for("admin_users"))

    user = User.query.get_or_404(user_id)
    user.banned = True
    db.session.commit()
    flash("User banned.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/unban/<int:user_id>", methods=["POST"])
@login_required
def unban_user(user_id):
    if not current_user.is_admin():
        flash("Not allowed", "danger")
        return redirect(url_for("posts"))

    user = User.query.get_or_404(user_id)
    user.banned = False
    db.session.commit()
    flash("User unbanned.", "success")
    return redirect(url_for("admin_users"))


# ---------------------- My Posts ----------------------
@app.route("/my/posts")
@login_required
def my_posts():
    jobs = Job.query.filter_by(user_id=current_user.id).order_by(Job.id.desc()).all()
    return render_template("my_posts.html", jobs=jobs)


# ---------------------- Run ----------------------
if __name__ == "__main__":
    # When first running locally you can use db.create_all() (already called above if file missing).
    # For production or when changing models, use Flask-Migrate instead.
    app.run(debug=True)
