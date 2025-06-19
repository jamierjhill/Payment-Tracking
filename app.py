# app.py
import os
from datetime import datetime, timedelta
from functools import wraps
import secrets
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, DecimalField, DateField, TimeField, SelectField, EmailField, PasswordField
from wtforms.validators import DataRequired, Email, Length, NumberRange
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
import logging
from logging.handlers import RotatingFileHandler

# Initialize Flask app
app = Flask(__name__)

# Configuration
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///tennis_coach.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    WTF_CSRF_TIME_LIMIT = 3600
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)
    
app.config.from_object(Config)

# Security enhancements
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
csrf = CSRFProtect(app)

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# Logging setup
if not app.debug:
    if not os.path.exists('logs'):
        os.mkdir('logs')
    file_handler = RotatingFileHandler('logs/tennis_coach.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Tennis Coach Invoice Manager startup')

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    academy_name = db.Column(db.String(200))
    hourly_rate = db.Column(db.Numeric(10, 2), default=50.00)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    lessons = db.relationship('Lesson', backref='coach', lazy=True, cascade='all, delete-orphan')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, index=True)
    email = db.Column(db.String(120), nullable=False, index=True)
    phone = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    coach_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    lessons = db.relationship('Lesson', backref='student', lazy=True)

class Lesson(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False, index=True)
    time = db.Column(db.Time, nullable=False)
    duration = db.Column(db.Numeric(3, 1), nullable=False)  # in hours
    rate = db.Column(db.Numeric(10, 2), nullable=False)
    lesson_type = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='pending', index=True)  # pending, paid, overdue
    invoice_number = db.Column(db.String(20), unique=True, nullable=False, index=True)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    paid_at = db.Column(db.DateTime)
    
    # Foreign keys
    coach_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    
    @property
    def total_amount(self):
        return float(self.duration * self.rate)
    
    @property
    def is_overdue(self):
        if self.status == 'paid':
            return False
        # Consider overdue if more than 7 days past lesson date
        return (datetime.now().date() - self.date).days > 7

# Forms
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
    student_email = EmailField('Student Email', validators=[DataRequired(), Email()])
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
        ('intensive', 'Intensive')
    ], validators=[DataRequired()])
    notes = StringField('Notes', validators=[Length(max=500)])

# Login manager
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper functions
def generate_invoice_number():
    """Generate unique invoice number"""
    import random
    while True:
        number = f"INV-{random.randint(10000, 99999)}"
        if not Lesson.query.filter_by(invoice_number=number).first():
            return number

def update_overdue_lessons():
    """Update lessons status to overdue"""
    overdue_lessons = Lesson.query.filter(
        Lesson.status == 'pending',
        Lesson.date < datetime.now().date() - timedelta(days=7)
    ).all()
    
    for lesson in overdue_lessons:
        lesson.status = 'overdue'
    
    if overdue_lessons:
        db.session.commit()

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('landing.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Check if user already exists
        if User.query.filter_by(username=form.username.data).first():
            flash('Username already exists. Please choose a different one.', 'error')
            return render_template('register.html', form=form)
        
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already registered. Please use a different email.', 'error')
            return render_template('register.html', form=form)
        
        # Create new user
        user = User(
            username=form.username.data,
            email=form.email.data,
            name=form.name.data,
            academy_name=form.academy_name.data
        )
        user.set_password(form.password.data)
        
        try:
            db.session.add(user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Registration error: {e}')
            flash('An error occurred during registration. Please try again.', 'error')
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=True)
            session.permanent = True
            next_page = request.args.get('next')
            if not next_page or not next_page.startswith('/'):
                next_page = url_for('dashboard')
            return redirect(next_page)
        flash('Invalid username or password.', 'error')
    
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    update_overdue_lessons()
    
    # Get dashboard statistics
    lessons = Lesson.query.filter_by(coach_id=current_user.id).all()
    
    stats = {
        'pending': len([l for l in lessons if l.status == 'pending']),
        'paid': len([l for l in lessons if l.status == 'paid']),
        'overdue': len([l for l in lessons if l.status == 'overdue']),
        'total_revenue': sum(l.total_amount for l in lessons if l.status == 'paid')
    }
    
    # Get recent lessons
    recent_lessons = Lesson.query.filter_by(coach_id=current_user.id)\
                                 .order_by(Lesson.date.desc(), Lesson.time.desc())\
                                 .limit(10).all()
    
    form = LessonForm()
    form.rate.data = current_user.hourly_rate
    
    return render_template('dashboard.html', stats=stats, lessons=recent_lessons, form=form)

@app.route('/add_lesson', methods=['POST'])
@login_required
def add_lesson():
    form = LessonForm()
    if form.validate_on_submit():
        try:
            # Get or create student
            student = Student.query.filter_by(
                email=form.student_email.data,
                coach_id=current_user.id
            ).first()
            
            if not student:
                student = Student(
                    name=form.student_name.data,
                    email=form.student_email.data,
                    coach_id=current_user.id
                )
                db.session.add(student)
                db.session.flush()  # Get student ID
            
            # Create lesson
            lesson = Lesson(
                date=form.date.data,
                time=form.time.data,
                duration=float(form.duration.data),
                rate=form.rate.data,
                lesson_type=form.lesson_type.data,
                notes=form.notes.data,
                invoice_number=generate_invoice_number(),
                coach_id=current_user.id,
                student_id=student.id
            )
            
            db.session.add(lesson)
            db.session.commit()
            flash('Lesson added successfully!', 'success')
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Add lesson error: {e}')
            flash('Error adding lesson. Please try again.', 'error')
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'{getattr(form, field).label.text}: {error}', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/api/lessons')
@login_required
def api_lessons():
    status_filter = request.args.get('status', 'all')
    
    query = Lesson.query.filter_by(coach_id=current_user.id)
    
    if status_filter != 'all':
        query = query.filter_by(status=status_filter)
    
    lessons = query.order_by(Lesson.date.desc(), Lesson.time.desc()).all()
    
    return jsonify([{
        'id': lesson.id,
        'student_name': lesson.student.name,
        'student_email': lesson.student.email,
        'date': lesson.date.isoformat(),
        'time': lesson.time.strftime('%H:%M'),
        'duration': float(lesson.duration),
        'rate': float(lesson.rate),
        'lesson_type': lesson.lesson_type,
        'status': lesson.status,
        'invoice_number': lesson.invoice_number,
        'total_amount': lesson.total_amount,
        'notes': lesson.notes
    } for lesson in lessons])

@app.route('/api/lesson/<int:lesson_id>/mark_paid', methods=['POST'])
@login_required
def mark_lesson_paid(lesson_id):
    lesson = Lesson.query.filter_by(id=lesson_id, coach_id=current_user.id).first()
    if not lesson:
        return jsonify({'error': 'Lesson not found'}), 404
    
    lesson.status = 'paid'
    lesson.paid_at = datetime.utcnow()
    
    try:
        db.session.commit()
        return jsonify({'success': True, 'message': 'Lesson marked as paid'})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Mark paid error: {e}')
        return jsonify({'error': 'Database error'}), 500

@app.route('/api/lesson/<int:lesson_id>/delete', methods=['DELETE'])
@login_required
def delete_lesson(lesson_id):
    lesson = Lesson.query.filter_by(id=lesson_id, coach_id=current_user.id).first()
    if not lesson:
        return jsonify({'error': 'Lesson not found'}), 404
    
    try:
        db.session.delete(lesson)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Lesson deleted'})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Delete lesson error: {e}')
        return jsonify({'error': 'Database error'}), 500

@app.route('/api/send_reminder/<int:lesson_id>', methods=['POST'])
@login_required
def send_reminder(lesson_id):
    lesson = Lesson.query.filter_by(id=lesson_id, coach_id=current_user.id).first()
    if not lesson:
        return jsonify({'error': 'Lesson not found'}), 404
    
    # In a real app, you would send an actual email here
    # For now, just simulate the action
    app.logger.info(f'Payment reminder sent for lesson {lesson.id} to {lesson.student.email}')
    
    return jsonify({
        'success': True, 
        'message': f'Payment reminder sent to {lesson.student.name}'
    })

@app.route('/api/send_bulk_reminders', methods=['POST'])
@login_required
def send_bulk_reminders():
    unpaid_lessons = Lesson.query.filter_by(coach_id=current_user.id)\
                                 .filter(Lesson.status.in_(['pending', 'overdue'])).all()
    
    # In a real app, you would send actual emails here
    for lesson in unpaid_lessons:
        app.logger.info(f'Bulk reminder sent for lesson {lesson.id} to {lesson.student.email}')
    
    return jsonify({
        'success': True,
        'message': f'{len(unpaid_lessons)} payment reminders sent!'
    })

@app.route('/invoice/<int:lesson_id>')
@login_required
def view_invoice(lesson_id):
    lesson = Lesson.query.filter_by(id=lesson_id, coach_id=current_user.id).first()
    if not lesson:
        flash('Invoice not found.', 'error')
        return redirect(url_for('dashboard'))
    
    return render_template('invoice.html', lesson=lesson, coach=current_user)

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('errors/500.html'), 500

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('errors/403.html'), 403

# CLI commands
@app.cli.command()
def init_db():
    """Initialize the database."""
    db.create_all()
    print('Database initialized.')

@app.cli.command()
def create_admin():
    """Create an admin user."""
    username = input('Username: ')
    email = input('Email: ')
    password = input('Password: ')
    name = input('Full Name: ')
    
    if User.query.filter_by(username=username).first():
        print('Username already exists.')
        return
    
    user = User(username=username, email=email, name=name, academy_name='Admin Academy')
    user.set_password(password)
    
    db.session.add(user)
    db.session.commit()
    print(f'Admin user {username} created successfully.')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    # Development server settings
    app.run(debug=True, host='127.0.0.1', port=5000)