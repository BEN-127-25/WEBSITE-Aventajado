from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from functools import wraps
from app import db
from app.models import User, Job, JobApplication, ApplicantPost

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


# ====================================================
# 🔐 ADMIN ACCESS ONLY
# ====================================================
def admin_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            flash("Admin access required.", "danger")
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return wrapped


# ====================================================
# 👥 ADMIN — MANAGE USERS
# ====================================================
@admin_bp.route('/users')
@login_required
@admin_required
def admin_users():
    q = request.args.get("q", "").strip()
    page = request.args.get("page", 1, type=int)

    query = User.query.order_by(User.id.asc())

    if q:
        query = query.filter(
            (User.username.ilike(f"%{q}%")) |
            (User.email.ilike(f"%{q}%"))
        )

    pagination = query.paginate(page=page, per_page=10, error_out=False)

    return render_template(
        "admin_users.html",
        users=pagination.items,
        pagination=pagination,
        q=q
    )


# ====================================================
# 🚫 BAN / UNBAN USER
# ====================================================
@admin_bp.route("/ban/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def ban_user(user_id):
    if user_id == current_user.id:
        flash("You cannot ban yourself.", "warning")
        return redirect(url_for("admin.admin_users"))

    user = User.query.get_or_404(user_id)
    user.banned = True
    db.session.commit()

    flash(f"User {user.username} banned.", "success")
    return redirect(url_for("admin.admin_users"))


@admin_bp.route("/unban/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def unban_user(user_id):
    user = User.query.get_or_404(user_id)
    user.banned = False
    db.session.commit()

    flash(f"User {user.username} unbanned.", "success")
    return redirect(url_for("admin.admin_users"))


# ====================================================
# ✔ APPROVE OR REJECT REGISTRATION
# ====================================================
@admin_bp.route('/update_user_status/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def update_user_status(user_id):
    action = request.form.get("action")
    user = User.query.get_or_404(user_id)

    if action == "approve":
        user.status = "approved"
        flash(f"User {user.username} approved.", "success")

    elif action == "reject":
        user.status = "rejected"
        flash(f"User {user.username} rejected.", "danger")

    db.session.commit()
    return redirect(url_for("admin.admin_users"))


# ====================================================
# 📝 ADMIN — VIEW ALL JOB POSTS
# ====================================================
@admin_bp.route("/job_posts")
@login_required
@admin_required
def job_posts():
    posts = Job.query.order_by(Job.id.desc()).all()
    return render_template("admin_job_posts.html", posts=posts)


# ====================================================
# 🔍 ADMIN — VIEW SINGLE JOB
# ====================================================
@admin_bp.route("/job_posts/view/<int:job_id>")
@login_required
@admin_required
def view_job_post(job_id):
    job = Job.query.get_or_404(job_id)
    applications = JobApplication.query.filter_by(job_id=job_id).all()

    return render_template(
        "admin_view_job_post.html",
        job=job,
        applications=applications
    )


# ====================================================
# ❌ ADMIN — DELETE JOB POST
# ====================================================
@admin_bp.route("/delete_job_post/<int:job_id>", methods=["POST"])
@login_required
@admin_required
def delete_job_post(job_id):
    job = Job.query.get_or_404(job_id)
    db.session.delete(job)
    db.session.commit()

    flash("Job post deleted.", "success")
    return redirect(url_for("admin.job_posts"))


# ====================================================
# 👤 ADMIN — VIEW APPLICANT POSTS
# ====================================================
@admin_bp.route("/applicant_posts")
@login_required
@admin_required
def view_applicant_posts():
    posts = ApplicantPost.query.order_by(ApplicantPost.id.desc()).all()
    return render_template("admin_applicant_posts.html", posts=posts)


# ====================================================
# 🌐 OPTIONAL LANDING PAGE
# ====================================================
@admin_bp.route("/landing")
def landing():
    return render_template("landing.html")

