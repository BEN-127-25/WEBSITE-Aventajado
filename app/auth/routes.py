import os
import secrets
from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from ..forms import RegisterForm, LoginForm, ProfileForm
from ..models import User
from .. import db
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

        # ALL OTHER USERS → job posts page
        return redirect(url_for('jobs.posts'))

    return render_template('home.html')


# =====================================================
# ABOUT US
# =====================================================
@auth_bp.route('/about')
@login_required
def about():
    return render_template('about.html')


# =====================================================
# REGISTER (FULLY FIXED VERSION — NO DUPLICATES)
# =====================================================
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    # Check if an admin already exists
    admin_exists = User.query.filter_by(role="admin").first() is not None

    if form.validate_on_submit():

        username = form.username.data.strip()
        email = form.email.data.strip() if form.email.data else None
        pw_hash = generate_password_hash(form.password.data)
        role = form.role.data

        # -----------------------------------------------
        # BLOCK unauthorized creation of admin accounts
        # -----------------------------------------------
        if role == "admin":
            # FIRST ADMIN EVER → allowed
            if not admin_exists:
                status = "approved"

            # Other admins → only existing admin may create more
            elif not current_user.is_authenticated or not current_user.is_admin():
                flash("Only an admin can create another admin account.", "danger")
                return redirect(url_for("auth.register"))
            else:
                status = "approved"   # admin creates admin

        else:
            # For ALL non-admin roles
            status = "pending"

        # Admin creating user → auto-approved users?
        if current_user.is_authenticated and current_user.is_admin() and role != "admin":
            # Keep customers/employees/employers pending
            status = "pending"

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

        # Admin creating user → redirect to admin panel
        if current_user.is_authenticated and current_user.is_admin():
            flash(f"User '{username}' registered successfully.", "success")
            return redirect(url_for('admin.admin_users'))

        # Normal users → pending approval
        if status == "pending":
            flash("Your account has been created and is pending admin approval.", "warning")
        else:
            flash("Admin account created successfully.", "success")

        return redirect(url_for('auth.login'))

    return render_template('register.html', form=form)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():

        # User can type username OR email
        input_value = form.username.data.strip()

        user = User.query.filter(
            (User.username == input_value) | (User.email == input_value)
        ).first()

        if not user or not check_password_hash(user.password_hash, form.password.data):
            flash("Invalid login credentials.", "danger")
            return redirect(url_for('auth.login'))

        if user.status != "approved":
            flash("Your account is pending approval.", "warning")
            return redirect(url_for('auth.login'))
        login_user(user)
        flash("Welcome back!", "success")

        if user.role == "admin":
            return redirect(url_for("admin.admin_users"))

        return redirect(url_for("jobs.posts"))

    return render_template("login.html", form=form)


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

        # Password
        if form.password.data:
            current_user.password_hash = generate_password_hash(form.password.data)
            updated = True

        # Profile Picture
        if form.profile_picture.data:
            if current_user.profile_picture:
                old_pic = os.path.join(
                    current_app.root_path, 
                    'static/profile_pics', 
                    current_user.profile_picture
                )
                if os.path.exists(old_pic):
                    os.remove(old_pic)

            new_pic = save_profile_picture(form.profile_picture.data)
            current_user.profile_picture = new_pic
            updated = True

        # Resume Upload
        if form.resume.data:
            if current_user.resume_filename:
                old_resume = os.path.join(
                    current_app.root_path, 
                    'static/uploads', 
                    current_user.resume_filename
                )
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

        if updated:
            db.session.commit()
            flash("Profile updated successfully!", "success")
        else:
            flash("No changes detected.", "info")

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
