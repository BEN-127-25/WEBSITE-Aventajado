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
    username = StringField("Username", validators=[Optional(), Length(min=3, max=80)])
    email = StringField("Email", validators=[Optional(), Email(), Length(max=150)])

    first_name = StringField("First Name", validators=[Optional(), Length(max=50)])
    last_name = StringField("Last Name", validators=[Optional(), Length(max=50)])

    password = PasswordField("New Password", validators=[Optional(), Length(min=6)])

    profile_picture = FileField(
        "Profile Picture",
        validators=[Optional(), FileAllowed(["jpg", "jpeg", "png"])]
    )

    # 🔥 Resume field used by your route
    resume = FileField(
        "Resume (PDF)",
        validators=[Optional(), FileAllowed(["pdf"])]
    )

    submit = SubmitField("Update Profile")


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

    experience = StringField("Experience Required", validators=[Optional()])

    # 🔥 REQUIRED — your route expects this!
    degree = StringField("Degree Required", validators=[Optional()])

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
