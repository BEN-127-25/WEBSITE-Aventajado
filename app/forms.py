from flask_wtf import FlaskForm
from wtforms import (
    StringField, PasswordField, SubmitField,
    TextAreaField, SelectField, FileField
)
from wtforms.validators import (
    DataRequired, Length, EqualTo, Optional,
    Email, ValidationError
)
from flask_wtf.file import FileAllowed
from app.models import User


# ================================
# REGISTER FORM
# ================================
class RegisterForm(FlaskForm):
    username = StringField(
        'Username',
        validators=[DataRequired(), Length(min=3, max=25)]
    )

    email = StringField(
        'Email',
        validators=[DataRequired(), Email()]
    )

    password = PasswordField(
        'Password',
        validators=[DataRequired(), Length(min=6)]
    )

    confirm = PasswordField(
        'Confirm Password',
        validators=[DataRequired(), EqualTo('password')]
    )

    # Roles allowed to be selected. Admin will still be blocked at route level.
    role = SelectField(
        'Role',
        choices=[
            ('applicant', 'Applicant'),
            ('employer', 'Employer'),
            ('admin', 'Admin')
        ],
        validators=[DataRequired()]
    )

    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data.strip()).first()
        if user:
            raise ValidationError("Username already taken.")

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data.strip()).first()
        if user:
            raise ValidationError("Email already in use.")


# ================================
# LOGIN FORM
# ================================
class LoginForm(FlaskForm):
    username = StringField('Username or Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


# ================================
# PROFILE FORM
# ================================
class ProfileForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    email = StringField("Email", validators=[Optional(), Email()])
    
    # Optional new password
    password = PasswordField("New Password (optional)", validators=[Optional()])

    profile_picture = FileField(
        "Upload Profile Picture",
        validators=[FileAllowed(["jpg", "jpeg", "png", "gif"])]
    )

    resume = FileField(
        "Upload Resume",
        validators=[FileAllowed(["pdf", "doc", "docx"])]
    )

    submit = SubmitField("Save Changes")


# ================================
# APPLICANT POST FORM
# ================================
class ApplicantPostForm(FlaskForm):
    job_title = StringField(
        "Job Title You're Applying For",
        validators=[DataRequired()]
    )

    description = TextAreaField(
        "Describe Yourself / Why You Apply",
        validators=[DataRequired()]
    )

    experience = TextAreaField(
        "Your Experience",
        validators=[Optional()]
    )

    resume_file = FileField(
        "Upload Resume",
        validators=[Optional(), FileAllowed(["pdf"], "PDF only!")]
    )

    submit = SubmitField("Post Application")


# ================================
# EMPLOYER POST FORM
# ================================
class EmployerPostForm(FlaskForm):
    job_title = StringField("Job Title", validators=[DataRequired()])
    company_name = StringField("Company Name", validators=[DataRequired()])
    description = TextAreaField("Job Description", validators=[DataRequired()])
    experience = TextAreaField("Required Experience", validators=[Optional()])
    submit = SubmitField("Post Job")


# ================================
# UNIVERSAL JOB CREATION (ADMIN)
# ================================
class CreateJobForm(FlaskForm):
    job_title = StringField("Job Title", validators=[DataRequired(), Length(max=200)])
    company_name = StringField("Company Name", validators=[Optional(), Length(max=200)])
    
    description = TextAreaField("Description", validators=[Optional()])
    experience = TextAreaField("Experience", validators=[Optional()])

    # Only used if admin is creating applicant post, optional
    resume_file = FileField(
        "Applicant Resume (Optional)",
        validators=[Optional(), FileAllowed(["pdf"], "PDF only!")]
    )

    submit = SubmitField("Create Job Post")
