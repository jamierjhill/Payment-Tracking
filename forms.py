# forms.py - Updated forms with email optional and lesson templates
from flask_wtf import FlaskForm
from wtforms import StringField, DecimalField, DateField, TimeField, SelectField, EmailField, PasswordField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, NumberRange, Optional
from wtforms.widgets import TextArea

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('Password', validators=[DataRequired()])

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    name = StringField('Full Name', validators=[DataRequired(), Length(max=100)])
    academy_name = StringField('Academy Name', validators=[Length(max=200)])

class LessonForm(FlaskForm):
    student_name = StringField('Student Name', validators=[DataRequired(), Length(max=100)])
    student_email = EmailField('Student Email', validators=[Optional(), Email()])
    student_phone = StringField('Student Phone', validators=[Optional(), Length(max=20)])
    date = DateField('Lesson Date', validators=[DataRequired()])
    time = TimeField('Lesson Time', validators=[DataRequired()])
    duration = SelectField('Duration', choices=[
        ('0.5', '30 minutes'),
        ('1.0', '1 hour'),
        ('1.5', '1.5 hours'),
        ('2.0', '2 hours')
    ], validators=[DataRequired()])
    rate = DecimalField('Hourly Rate (£)', validators=[DataRequired(), NumberRange(min=0)])
    lesson_type = SelectField('Lesson Type', choices=[
        ('individual', 'Individual'),
        ('group', 'Group'),
        ('intensive', 'Intensive'),
        ('stringing', 'Racquet Stringing')
    ], validators=[DataRequired()])
    notes = TextAreaField('Notes', validators=[Optional(), Length(max=500)])
    
    # Quick templates
    template = SelectField('Quick Template', choices=[
        ('', 'Select Template'),
        ('1hour_individual', '1 Hour Individual Lesson'),
        ('stringing', 'Racquet Stringing Service')
    ], validators=[Optional()])

# Add these template configurations
LESSON_TEMPLATES = {
    '1hour_individual': {
        'duration': '1.0',
        'lesson_type': 'individual',
        'notes': 'Standard 1-hour individual tennis lesson'
    },
    'stringing': {
        'duration': '0.5',
        'lesson_type': 'stringing',
        'notes': 'Professional racquet stringing service'
    }
}