from flask import (
    Blueprint, render_template, redirect, url_for, flash,
    request, send_from_directory, abort, current_app
)
from flask_login import login_required, current_user
from app import db
from app.models import Job, ApplicantPost, User, JobApplication
from app.forms import EmployerPostForm, ApplicantPostForm
from app.utils import save_resume
import os

jobs_bp = Blueprint("jobs", __name__, url_prefix="/jobs")


# ====================================================
# 🟢 SHOW ALL JOB POSTS (UPDATED to include Applicant Posts)
# ====================================================
@jobs_bp.route("/posts")
def posts():
    search_query = request.args.get("search", "").strip()
    experience_filter = request.args.get("experience", "").strip()
    degree_filter = request.args.get("degree", "").strip()
    status_filter = request.args.get("status", "").strip()

    # --- 1. Query Employer Job Posts ---
    jobs = Job.query
    
    # Text search on Job model
    if search_query:
        like = f"%{search_query}%"
        jobs = jobs.filter(
            db.or_(
                Job.title.ilike(like),
                Job.company.ilike(like),
                Job.description.ilike(like)
            )
        )

    # Filters on Job model
    if experience_filter:
        jobs = jobs.filter(Job.experience_required == experience_filter)

    if degree_filter:
        jobs = jobs.filter(Job.degree_required == degree_filter)

    if status_filter:
        jobs = jobs.filter(Job.status == status_filter)

    jobs = jobs.order_by(Job.id.desc()).all()
    
    # --- 2. Query Applicant Profiles (ApplicantPost) ---
    # NOTE: The search and filter logic above applies only to Job posts.
    # We will fetch all applicant posts and rely on the frontend for filtering/searching them.
    applicant_posts = ApplicantPost.query.order_by(ApplicantPost.id.desc()).all()


    # Dropdowns (only generated from Job posts)
    experience_options = sorted({
        j.experience_required for j in Job.query.all() if j.experience_required
    })
    degree_options = sorted({
        j.degree_required for j in Job.query.all() if j.degree_required
    })
    status_options = ["open", "pending", "taken"]

    return render_template(
        "posts.html",
        jobs=jobs,
        applicant_posts=applicant_posts,  # <<< NEW: Passing applicant posts to the template
        search_query=search_query,
        experience_filter=experience_filter,
        degree_filter=degree_filter,
        status_filter=status_filter,
        experience_options=experience_options,
        degree_options=degree_options,
        status_options=status_options
    )

# ====================================================
# 🟢 CREATE JOB POST
# ====================================================
@jobs_bp.route("/create", methods=["GET", "POST"])
@login_required
def create_post():

    if current_user.role == "applicant":
        form = ApplicantPostForm()
    else:
        form = EmployerPostForm()

    if form.validate_on_submit():

        # EMPLOYER CREATES A JOB POST
        if current_user.role == "employer":
            job = Job(
                user_id=current_user.id,
                role="employer",
                title=form.job_title.data,
                company=form.company_name.data,
                description=form.description.data,
                experience_required=form.experience.data,
                # --- FIXED: Added status field
                status="open" 
            )
            db.session.add(job)
            db.session.commit()

            flash("Your job post has been created!", "success")
            return redirect(url_for("jobs.posts"))

        # APPLICANT CREATES APPLICANT PROFILE (NOT A JOB POST)
        if current_user.role == "applicant":
            resume_file = save_resume(form.resume_file.data) if form.resume_file.data else None

            post = ApplicantPost(
                user_id=current_user.id,
                looking_for=form.job_title.data,
                experience=form.experience.data,
                description=form.description.data,
                resume_file=resume_file
            )
            db.session.add(post)
            db.session.commit()

            flash("Your applicant profile has been created!", "success")
            return redirect(url_for("jobs.applicant_posts"))

    return render_template("create_post.html", form=form)


# ====================================================
# 🟢 VIEW A JOB POST
# ====================================================
@jobs_bp.route("/view/<int:job_id>")
def view_post(job_id):
    job = Job.query.get_or_404(job_id)

    applications = JobApplication.query.filter_by(job_id=job.id).all()

    can_hire = (
        current_user.is_authenticated
        and current_user.role in ("employer", "admin")
        and current_user.id == job.user_id
    )

    return render_template(
        "view_post.html",
        job=job,
        applications=applications,
        can_hire=can_hire,
        # --- FIXED: Added current_app to resolve Jinja2 UndefinedError
        current_app=current_app 
    )


# ====================================================
# 🟢 APPLY TO A JOB
# ====================================================
@jobs_bp.route("/apply/<int:job_id>", methods=["GET", "POST"])
@login_required
def apply(job_id):
    job = Job.query.get_or_404(job_id)

    if current_user.role != "applicant":
        abort(403)

    form = ApplicantPostForm()

    if form.validate_on_submit():

        resume_file = save_resume(form.resume_file.data) if form.resume_file.data else None

        application = JobApplication(
            job_id=job.id,
            user_id=current_user.id,
            experience=form.experience.data,
            resume_file=resume_file
        )

        db.session.add(application)
        db.session.commit()

        flash("Application submitted successfully!", "success")
        return redirect(url_for("jobs.view_post", job_id=job.id))

    return render_template("apply.html", form=form, job=job)


# ====================================================
# 🟢 EMPLOYER VIEW MY JOB POSTS
# ====================================================
@jobs_bp.route("/my_posts")
@login_required
def my_posts():
    if current_user.role not in ("employer", "admin"):
        flash("You are not allowed to access this page.", "danger")
        return redirect(url_for("jobs.posts"))

    jobs = Job.query.filter_by(user_id=current_user.id).order_by(Job.id.desc()).all()

    return render_template("my_posts.html", jobs=jobs)


# ====================================================
# 🟢 VIEW RESUME (FIXED + SECURE)
# ====================================================
@jobs_bp.route("/resume/<int:application_id>")
@login_required
def view_resume(application_id):
    application = JobApplication.query.get_or_404(application_id)
    job = application.job

    # Permission checks
    is_applicant = (current_user.id == application.user_id)
    is_employer = (current_user.id == job.user_id)
    is_admin = (current_user.role == "admin")

    if not (is_applicant or is_employer or is_admin):
        abort(403)

    upload_path = os.path.join(current_app.root_path, "static/uploads")

    return send_from_directory(upload_path, application.resume_file, as_attachment=False)


# ====================================================
# 🟢 APPLICANT POSTS
# ====================================================
@jobs_bp.route("/applicant_posts")
def applicant_posts():
    posts = ApplicantPost.query.order_by(ApplicantPost.id.desc()).all()
    return render_template("applicant_posts.html", posts=posts)


# ====================================================
# 🟢 EMPLOYER HIRE APPLICANT
# ====================================================
@jobs_bp.route("/hire/<int:application_id>")
@login_required
def hire_applicant(application_id):
    application = JobApplication.query.get_or_404(application_id)
    job = application.job

    # Only job owner (employer) or admin can hire
    if current_user.id != job.user_id and current_user.role != "admin":
        abort(403)

    # Mark job as taken
    job.status = "taken"

    # Store hiring decision
    application.status = "hired"

    db.session.commit()

    flash(f"You have hired {application.user.first_name} {application.user.last_name}!", "success")
    return redirect(url_for("jobs.view_post", job_id=job.id))


# ====================================================
# 🟢 EDIT JOB POST
# ====================================================
@jobs_bp.route("/edit/<int:job_id>", methods=["GET", "POST"])
@login_required
def edit_post(job_id):
    job = Job.query.get_or_404(job_id)

    # Only job owner or admin can edit
    if current_user.id != job.user_id and current_user.role != "admin":
        abort(403)

    # Employer form
    form = EmployerPostForm(
        job_title=job.title,
        company_name=job.company,
        description=job.description,
        experience=job.experience_required,
        degree=job.degree_required
    )

    if form.validate_on_submit():
        job.title = form.job_title.data
        job.company = form.company_name.data
        job.description = form.description.data
        job.experience_required = form.experience.data
        job.degree_required = form.degree.data

        db.session.commit()

        flash("Job post updated successfully!", "success")
        return redirect(url_for("jobs.view_post", job_id=job.id))

    return render_template("edit_post.html", form=form, job=job)


# ====================================================
# 🟢 DELETE JOB POST
# ====================================================
@jobs_bp.route("/delete/<int:job_id>", methods=["POST"])
@login_required
def delete_post(job_id):
    job = Job.query.get_or_404(job_id)

    # Only job owner or admin can delete
    if current_user.id != job.user_id and current_user.role != "admin":
        abort(403)

    db.session.delete(job)
    db.session.commit()

    flash("Job post deleted successfully!", "success")
    return redirect(url_for("jobs.my_posts"))

# Add this function to jobs/routes.py

# ====================================================
# 🟢 UPDATE APPLICATION STATUS
# ====================================================
@jobs_bp.route("/update_application_status/<int:app_id>", methods=["POST"])
@login_required
def update_application_status(app_id):
    application = JobApplication.query.get_or_404(app_id)
    job = application.job
    
    # Permission check: Must be the job owner or an admin
    if current_user.id != job.user_id and current_user.role != "admin":
        abort(403)

    new_status = request.form.get("status")

    if new_status in ["pending", "approved", "taken"]:
        application.status = new_status
        db.session.commit()
        flash(f"Application status for {application.user.username} updated to {new_status}.", "success")
    else:
        flash("Invalid status selected.", "danger")

    # Redirect back to the view post page for context
    return redirect(url_for("jobs.view_post", job_id=job.id))

# ====================================================
# 🟢 VIEW APPLICANT POST RESUME (NEW + SECURE)
# ====================================================
@jobs_bp.route("/applicant_resume/<int:post_id>")
@login_required
def view_applicant_resume(post_id):
    post = ApplicantPost.query.get_or_404(post_id)
    
    # Permission checks
    is_applicant = (current_user.id == post.user_id)
    is_employer_or_admin = (current_user.role in ("employer", "admin"))
    
    if not (is_applicant or is_employer_or_admin):
        abort(403)
        
    if not post.resume_file:
        flash("Resume file not found for this applicant post.", "danger")
        # Redirect back to the applicant posts list
        return redirect(url_for("jobs.applicant_posts"))

    # Assuming resumes are stored in static/uploads
    upload_path = os.path.join(current_app.root_path, "static/uploads")
    
    # Return the file securely
    return send_from_directory(upload_path, post.resume_file, as_attachment=False)

# ====================================================
# 🟢 CONTACT APPLICANT (NEW)
# ====================================================
@jobs_bp.route("/contact_applicant/<int:user_id>")
@login_required
def contact_applicant(user_id):
    # Only employers and admins should use this feature
    if current_user.role not in ("employer", "admin"):
        abort(403)

    applicant = User.query.get_or_404(user_id)
    
    if applicant.email:
        # Redirects the user to their default email client (mailto protocol)
        return redirect(f"mailto:{applicant.email}?subject=Job%20Opportunity%20from%20Your%20Profile%20on%20Our%20Job%20Board")
    
    flash("Error: Applicant email address is not available.", "danger")
    return redirect(url_for("jobs.applicant_posts"))