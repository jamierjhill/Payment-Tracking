# app.py - Main Flask Application
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, CSRFProtect
from flask_wtf.csrf import validate_csrf
from wtforms import StringField, DecimalField, DateField, SelectField, TextAreaField, EmailField, PasswordField
from wtforms.validators import DataRequired, Email, Length, NumberRange
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from decimal import Decimal
import secrets
import os
from functools import wraps
import re
import sqlalchemy as sa

# Initialize Flask app
app = Flask(__name__)

# Security Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # 1 hour CSRF token validity
app.config['SESSION_COOKIE_SECURE'] = True  # HTTPS only
app.config['SESSION_COOKIE_HTTPONLY'] = True  # No JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)

# Database Configuration
database_url = os.environ.get('DATABASE_URL', 'sqlite:///tennis_invoices.db')
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
csrf = CSRFProtect(app)

# Database Models
class Coach(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    business_name = db.Column(db.String(200))
    phone = db.Column(db.String(20))
    address = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    students = db.relationship('Student', backref='coach', lazy=True, cascade='all, delete-orphan')
    invoices = db.relationship('Invoice', backref='coach', lazy=True, cascade='all, delete-orphan')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    coach_id = db.Column(db.Integer, db.ForeignKey('coach.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120))
    phone = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    invoices = db.relationship('Invoice', backref='student', lazy=True)

class Invoice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    coach_id = db.Column(db.Integer, db.ForeignKey('coach.id'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    invoice_number = db.Column(db.String(50), unique=True, nullable=False)
    date_issued = db.Column(db.Date, nullable=False, default=datetime.utcnow().date())
    due_date = db.Column(db.Date, nullable=False)
    amount = db.Column(sa.Numeric(10, 2), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(20), default='pending')  # pending, paid, overdue
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    paid_at = db.Column(db.DateTime)
    
    def generate_invoice_number(self, coach_id):
        """Generate unique invoice number"""
        today = datetime.now()
        prefix = f"INV-{coach_id}-{today.strftime('%Y%m')}"
        
        # Find the highest existing number for this month
        existing = db.session.query(Invoice.invoice_number)\
            .filter(Invoice.invoice_number.like(f"{prefix}%"))\
            .order_by(Invoice.invoice_number.desc())\
            .first()
        
        if existing:
            try:
                last_num = int(existing[0].split('-')[-1])
                new_num = last_num + 1
            except (ValueError, IndexError):
                new_num = 1
        else:
            new_num = 1
        
        return f"{prefix}-{new_num:03d}"

# Forms
class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])

class RegisterForm(FlaskForm):
    name = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=100)])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    business_name = StringField('Business Name', validators=[Length(max=200)])
    phone = StringField('Phone', validators=[Length(max=20)])
    address = TextAreaField('Address')

class StudentForm(FlaskForm):
    name = StringField('Student Name', validators=[DataRequired(), Length(min=2, max=100)])
    email = EmailField('Email', validators=[Email()])
    phone = StringField('Phone', validators=[Length(max=20)])

class InvoiceForm(FlaskForm):
    student_id = SelectField('Student', coerce=int, validators=[DataRequired()])
    amount = DecimalField('Amount ($)', validators=[DataRequired(), NumberRange(min=0.01, max=9999.99)])
    description = TextAreaField('Description', validators=[DataRequired(), Length(max=500)])
    due_date = DateField('Due Date', validators=[DataRequired()])

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'coach_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Input validation helpers
def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def sanitize_input(text):
    """Basic input sanitization"""
    if not text:
        return text
    return text.strip()[:500]  # Limit length and strip whitespace

# Routes
@app.route('/')
def index():
    if 'coach_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    
    if form.validate_on_submit():
        # Check if email already exists
        if Coach.query.filter_by(email=form.email.data.lower()).first():
            flash('Email already registered. Please use a different email.', 'error')
            return render_template('register.html', form=form)
        
        # Create new coach
        coach = Coach(
            name=sanitize_input(form.name.data),
            email=form.email.data.lower(),
            business_name=sanitize_input(form.business_name.data),
            phone=sanitize_input(form.phone.data),
            address=sanitize_input(form.address.data)
        )
        coach.set_password(form.password.data)
        
        try:
            db.session.add(coach)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('Registration failed. Please try again.', 'error')
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    
    if form.validate_on_submit():
        coach = Coach.query.filter_by(email=form.email.data.lower()).first()
        
        if coach and coach.check_password(form.password.data) and coach.is_active:
            session['coach_id'] = coach.id
            session['coach_name'] = coach.name
            session.permanent = True
            flash(f'Welcome back, {coach.name}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'error')
    
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    coach_id = session['coach_id']
    
    # Get dashboard statistics
    total_students = Student.query.filter_by(coach_id=coach_id, is_active=True).count()
    
    pending_invoices = Invoice.query.filter_by(coach_id=coach_id, status='pending').count()
    
    total_pending_amount = db.session.query(db.func.sum(Invoice.amount))\
        .filter_by(coach_id=coach_id, status='pending').scalar() or 0
    
    # Recent invoices
    recent_invoices = Invoice.query.filter_by(coach_id=coach_id)\
        .order_by(Invoice.created_at.desc())\
        .limit(5).all()
    
    # Overdue invoices
    today = datetime.now().date()
    overdue_invoices = Invoice.query.filter(
        Invoice.coach_id == coach_id,
        Invoice.status == 'pending',
        Invoice.due_date < today
    ).all()
    
    return render_template('dashboard.html',
                         total_students=total_students,
                         pending_invoices=pending_invoices,
                         total_pending_amount=total_pending_amount,
                         recent_invoices=recent_invoices,
                         overdue_invoices=overdue_invoices)

@app.route('/students')
@login_required
def students():
    coach_id = session['coach_id']
    students = Student.query.filter_by(coach_id=coach_id, is_active=True)\
        .order_by(Student.name).all()
    return render_template('students.html', students=students)

@app.route('/students/add', methods=['GET', 'POST'])
@login_required
def add_student():
    form = StudentForm()
    
    if form.validate_on_submit():
        student = Student(
            coach_id=session['coach_id'],
            name=sanitize_input(form.name.data),
            email=form.email.data.lower() if form.email.data else None,
            phone=sanitize_input(form.phone.data)
        )
        
        try:
            db.session.add(student)
            db.session.commit()
            flash('Student added successfully!', 'success')
            return redirect(url_for('students'))
        except Exception as e:
            db.session.rollback()
            flash('Failed to add student. Please try again.', 'error')
    
    return render_template('add_student.html', form=form)

@app.route('/invoices')
@login_required
def invoices():
    coach_id = session['coach_id']
    status_filter = request.args.get('status', 'all')
    
    query = Invoice.query.filter_by(coach_id=coach_id)
    
    if status_filter != 'all':
        query = query.filter_by(status=status_filter)
    
    invoices = query.order_by(Invoice.created_at.desc()).all()
    
    return render_template('invoices.html', invoices=invoices, status_filter=status_filter)

@app.route('/invoices/create', methods=['GET', 'POST'])
@login_required
def create_invoice():
    form = InvoiceForm()
    coach_id = session['coach_id']
    
    # Populate student choices
    students = Student.query.filter_by(coach_id=coach_id, is_active=True)\
        .order_by(Student.name).all()
    form.student_id.choices = [(s.id, s.name) for s in students]
    
    if not students:
        flash('You need to add students before creating invoices.', 'warning')
        return redirect(url_for('add_student'))
    
    if form.validate_on_submit():
        invoice = Invoice(
            coach_id=coach_id,
            student_id=form.student_id.data,
            amount=form.amount.data,
            description=sanitize_input(form.description.data),
            due_date=form.due_date.data
        )
        
        # Generate invoice number
        invoice.invoice_number = invoice.generate_invoice_number(coach_id)
        
        try:
            db.session.add(invoice)
            db.session.commit()
            flash('Invoice created successfully!', 'success')
            return redirect(url_for('invoices'))
        except Exception as e:
            db.session.rollback()
            flash('Failed to create invoice. Please try again.', 'error')
    
    return render_template('create_invoice.html', form=form)

@app.route('/invoices/<int:invoice_id>/mark_paid', methods=['POST'])
@login_required
def mark_paid(invoice_id):
    try:
        validate_csrf(request.form.get('csrf_token'))
    except:
        flash('Security error. Please try again.', 'error')
        return redirect(url_for('invoices'))
    
    invoice = Invoice.query.filter_by(
        id=invoice_id, 
        coach_id=session['coach_id']
    ).first_or_404()
    
    if invoice.status != 'paid':
        invoice.status = 'paid'
        invoice.paid_at = datetime.utcnow()
        
        try:
            db.session.commit()
            flash('Invoice marked as paid!', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Failed to update invoice. Please try again.', 'error')
    
    return redirect(url_for('invoices'))

@app.route('/api/dashboard_stats')
@login_required
def dashboard_stats():
    """API endpoint for dashboard statistics"""
    coach_id = session['coach_id']
    
    # Calculate overdue invoices
    today = datetime.now().date()
    Invoice.query.filter(
        Invoice.coach_id == coach_id,
        Invoice.status == 'pending',
        Invoice.due_date < today
    ).update({'status': 'overdue'})
    db.session.commit()
    
    stats = {
        'total_students': Student.query.filter_by(coach_id=coach_id, is_active=True).count(),
        'pending_invoices': Invoice.query.filter_by(coach_id=coach_id, status='pending').count(),
        'overdue_invoices': Invoice.query.filter_by(coach_id=coach_id, status='overdue').count(),
        'total_pending': float(db.session.query(db.func.sum(Invoice.amount))
                              .filter_by(coach_id=coach_id, status='pending').scalar() or 0)
    }
    
    return jsonify(stats)

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', 
                         title='Page Not Found', 
                         message='The page you are looking for does not exist.'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('error.html',
                         title='Server Error',
                         message='An internal server error occurred.'), 500

@app.errorhandler(403)
def forbidden(error):
    return render_template('error.html',
                         title='Access Forbidden',
                         message='You do not have permission to access this resource.'), 403

# Security headers
@app.after_request
def after_request(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = ("default-src 'self'; "
                                                   "script-src 'self' 'unsafe-inline'; "
                                                   "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                                                   "font-src 'self' https://cdn.jsdelivr.net")
    return response

# Database initialization
def create_tables():
    """Create database tables"""
    with app.app_context():
        db.create_all()

if __name__ == '__main__':
    create_tables()
    # Use debug=False in production
    app.run(debug=os.environ.get('FLASK_ENV') == 'development', 
            host=os.environ.get('HOST', '127.0.0.1'),
            port=int(os.environ.get('PORT', 5000)))