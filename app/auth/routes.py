import os
import secrets
from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from app.forms import RegisterForm, LoginForm, ProfileForm
from app import db
from app.models import User
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user
from app.utils import save_resume
from werkzeug.utils import secure_filename

auth_bp = Blueprint('auth', __name__)

# =====================================================
# HOME / LANDING
# =====================================================
@auth_bp.route('/')
def index():
    if current_user.is_authenticated:

        # ADMIN REDIRECT
        if current_user.role == 'admin':
            return redirect(url_for('admin.admin_users'))

        # APPLICANT / EMPLOYEE / EMPLOYER / RECRUITER
        # All authenticated users are redirected to the job posts page.
        return redirect(url_for('jobs.posts'))

    return render_template('home.html')


# =====================================================
# ABOUT US  (visible only when logged in)
# =====================================================
@auth_bp.route('/about')
@login_required
def about():
    return render_template('about.html')


# =====================================================
# REGISTER (SECURED + ADMIN CAN CREATE ACCOUNTS)
# =====================================================
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    # If a normal user tries to select admin → block it
    if form.role.data == "admin" and (
        not current_user.is_authenticated or not current_user.is_admin()
    ):
        flash("You are not allowed to register an admin account.", "danger")
        return redirect(url_for("auth.register"))

    if form.validate_on_submit():

        username = form.username.data.strip()
        email = form.email.data.strip() if form.email.data else None
        pw_hash = generate_password_hash(form.password.data)
        role = form.role.data

        # New user is ALWAYS unapproved at first (except admin creation by admin)
        status = "pending"

        # If admin is creating another admin → auto approve
        if current_user.is_authenticated and current_user.is_admin():
            status = "approved"

        user = User(
            username=username,
            email=email,
            password_hash=pw_hash,
            role=role,
            status=status
        )

        db.session.add(user)

        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            flash('Registration failed: ' + str(e), 'danger')
            return redirect(url_for('auth.register'))

        # ADMIN creating accounts → no need for approval message
        if current_user.is_authenticated and current_user.is_admin():
            flash(f"User '{username}' registered successfully.", "success")
            return redirect(url_for('admin.admin_users'))

        # Normal registrants → pending approval message
        flash('Your account has been created and is pending admin approval.', 'warning')
        return redirect(url_for('auth.login'))

    # Debug: Show validation errors if form fails
    elif request.method == 'POST':
        print("Form validation errors:", form.errors)

    return render_template('register.html', form=form)

# =====================================================
# LOGIN (UPDATED for Admin Approval Check)
# =====================================================
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():

        login_input = form.username.data.strip()
        password = form.password.data

        # Allow username or email login
        if '@' in login_input:
            user = User.query.filter_by(email=login_input).first()
        else:
            user = User.query.filter_by(username=login_input).first()

        # Invalid credentials
        if not user or not check_password_hash(user.password_hash, password):
            flash('Invalid username/email or password.', 'danger')
            return redirect(url_for('auth.login'))
        
        # CRITICAL CHECK: Block login if not approved
        # Using getattr with a default of True handles cases where 'is_approved' might not exist (e.g., for old admin accounts)
        if not getattr(user, 'is_approved', True): 
            flash('Your account is pending admin approval. Please wait for an administrator to review your registration.', 'danger')
            return redirect(url_for('auth.login')) 

        # Check if banned
        if getattr(user, 'banned', False):
            flash('Your account is banned. Contact admin.', 'danger')
            return redirect(url_for('auth.login'))

        # Login
        login_user(user)
        flash('Logged in successfully.', 'success')

        next_page = request.args.get('next')

        # Redirect based on role
        if user.role == 'admin':
            return redirect(next_page or url_for('admin.admin_users'))

        elif user.role in ('employer', 'employee', 'recruiter', 'applicant'):
            return redirect(next_page or url_for('jobs.posts'))

        return redirect(next_page or url_for('auth.index'))

    return render_template('login.html', form=form)


# =====================================================
# LOGOUT
# =====================================================
@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.', 'info')
    return redirect(url_for('auth.index'))


# =====================================================
# SAVE PROFILE PICTURE
# =====================================================
def save_profile_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(current_app.root_path, 'static/profile_pics', picture_fn)

    os.makedirs(os.path.dirname(picture_path), exist_ok=True)
    form_picture.save(picture_path)

    return picture_fn


# =====================================================
# PROFILE PAGE
# =====================================================
@auth_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileForm(obj=current_user)

    if form.validate_on_submit():
        updated = False

        # Username
        if form.username.data and form.username.data != current_user.username:
            current_user.username = form.username.data
            updated = True

        # Email
        if form.email.data and form.email.data != current_user.email:
            current_user.email = form.email.data
            updated = True

        # Change Password
        if form.password.data:
            current_user.password_hash = generate_password_hash(form.password.data)
            updated = True

        # Profile Picture
        if form.profile_picture.data:

            if current_user.profile_picture:
                old_pic = os.path.join(current_app.root_path, 'static/profile_pics', current_user.profile_picture)
                if os.path.exists(old_pic):
                    os.remove(old_pic)

            new_pic = save_profile_picture(form.profile_picture.data)
            current_user.profile_picture = new_pic
            updated = True

        # Resume Upload
        if form.resume.data:

            if current_user.resume_filename:
                old_resume = os.path.join(current_app.root_path, 'static/uploads', current_user.resume_filename)
                if os.path.exists(old_resume):
                    os.remove(old_resume)

            new_resume = save_resume(form.resume.data)
            current_user.resume_filename = new_resume
            updated = True
            
        # First Name
        if form.first_name.data and form.first_name.data != current_user.first_name:
            current_user.first_name = form.first_name.data
            updated = True
            
        # Last Name
        if form.last_name.data and form.last_name.data != current_user.last_name:
            current_user.last_name = form.last_name.data
            updated = True


        # Apply changes
        if updated:
            db.session.commit()
            flash("✅ Profile updated successfully!", "success")
        else:
            flash("⚠️ No changes detected.", "info")

        return redirect(url_for('auth.profile'))

    return render_template('profile.html', form=form, user=current_user)


# =====================================================
# VIEW ANOTHER USER'S PROFILE (PUBLIC)
# =====================================================
@auth_bp.route('/profile/<int:user_id>')
@login_required
def view_profile(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('profile.html', user=user)