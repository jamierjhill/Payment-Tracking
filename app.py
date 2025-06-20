# app.py - Main Flask Application
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, CSRFProtect
from flask_wtf.csrf import validate_csrf
from wtforms import StringField, DecimalField, DateField, SelectField, TextAreaField, EmailField, PasswordField
from wtforms.validators import DataRequired, Email, Length, NumberRange, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from decimal import Decimal
import secrets
import os
from functools import wraps
import re
import sqlalchemy as sa
import logging

# Initialize Flask app
app = Flask(__name__)

# Security Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # 1 hour CSRF token validity
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') != 'development'
app.config['SESSION_COOKIE_HTTPONLY'] = True  # No JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)

# Database Configuration
database_url = os.environ.get('DATABASE_URL', 'sqlite:///tennis_invoices.db')
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
}

# Initialize extensions
db = SQLAlchemy(app)
csrf = CSRFProtect(app)

# Configure logging
if not app.debug:
    logging.basicConfig(level=logging.INFO)

# Database Models
class Coach(db.Model):
    __tablename__ = 'coaches'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    business_name = db.Column(db.String(200))
    phone = db.Column(db.String(20))
    address = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    is_active = db.Column(db.Boolean, default=True, index=True)
    last_login = db.Column(db.DateTime)
    
    # Relationships
    students = db.relationship('Student', backref='coach', lazy=True, cascade='all, delete-orphan')
    invoices = db.relationship('Invoice', backref='coach', lazy=True, cascade='all, delete-orphan')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<Coach {self.email}>'

class Student(db.Model):
    __tablename__ = 'students'
    
    id = db.Column(db.Integer, primary_key=True)
    coach_id = db.Column(db.Integer, db.ForeignKey('coaches.id'), nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False, index=True)
    email = db.Column(db.String(120), index=True)
    phone = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    is_active = db.Column(db.Boolean, default=True, index=True)
    
    # Relationships
    invoices = db.relationship('Invoice', backref='student', lazy=True)
    
    def __repr__(self):
        return f'<Student {self.name}>'

class Invoice(db.Model):
    __tablename__ = 'invoices'
    
    id = db.Column(db.Integer, primary_key=True)
    coach_id = db.Column(db.Integer, db.ForeignKey('coaches.id'), nullable=False, index=True)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id'), nullable=False, index=True)
    invoice_number = db.Column(db.String(50), unique=True, nullable=False, index=True)
    date_issued = db.Column(db.Date, nullable=False, default=datetime.utcnow().date(), index=True)
    due_date = db.Column(db.Date, nullable=False, index=True)
    amount = db.Column(sa.Numeric(10, 2), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending', index=True)  # pending, paid, overdue
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    paid_at = db.Column(db.DateTime)
    
    def generate_invoice_number(self, coach_id):
        """Generate unique invoice number"""
        today = datetime.now()
        prefix = f"INV-{coach_id}-{today.strftime('%Y%m')}"
        
        # Find the highest existing number for this month
        existing = db.session.query(Invoice.invoice_number)\
            .filter(Invoice.coach_id == coach_id,
                   Invoice.invoice_number.like(f"{prefix}%"))\
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
    
    def is_overdue(self):
        """Check if invoice is overdue"""
        return self.status == 'pending' and self.due_date < datetime.now().date()
    
    def __repr__(self):
        return f'<Invoice {self.invoice_number}>'

# Custom Validators
def validate_phone(form, field):
    """Custom phone number validator"""
    if field.data:
        # Remove all non-digit characters
        phone = re.sub(r'\D', '', field.data)
        if len(phone) < 10 or len(phone) > 15:
            raise ValidationError('Phone number must be between 10-15 digits')

# Forms
class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])

class RegisterForm(FlaskForm):
    name = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=100)])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    business_name = StringField('Business Name', validators=[Length(max=200)])
    phone = StringField('Phone', validators=[Length(max=20), validate_phone])
    address = TextAreaField('Address', validators=[Length(max=500)])
    
    def validate_email(self, email):
        coach = Coach.query.filter_by(email=email.data.lower()).first()
        if coach:
            raise ValidationError('Email already registered. Please use a different email.')

class StudentForm(FlaskForm):
    name = StringField('Student Name', validators=[DataRequired(), Length(min=2, max=100)])
    email = EmailField('Email', validators=[Email()])
    phone = StringField('Phone', validators=[Length(max=20), validate_phone])

class InvoiceForm(FlaskForm):
    student_id = SelectField('Student', coerce=int, validators=[DataRequired()])
    amount = DecimalField('Amount ($)', validators=[DataRequired(), NumberRange(min=0.01, max=99999.99)], places=2)
    description = TextAreaField('Description', validators=[DataRequired(), Length(min=5, max=500)])
    due_date = DateField('Due Date', validators=[DataRequired()])
    
    def validate_due_date(self, due_date):
        if due_date.data and due_date.data < datetime.now().date():
            raise ValidationError('Due date cannot be in the past.')

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
def validate_email_format(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def sanitize_input(text, max_length=500):
    """Basic input sanitization"""
    if not text:
        return text
    return text.strip()[:max_length]

# Routes
@app.route('/')
def index():
    if 'coach_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'coach_id' in session:
        return redirect(url_for('dashboard'))
        
    form = RegisterForm()
    
    if form.validate_on_submit():
        try:
            # Create new coach
            coach = Coach(
                name=sanitize_input(form.name.data, 100),
                email=form.email.data.lower().strip(),
                business_name=sanitize_input(form.business_name.data, 200),
                phone=sanitize_input(form.phone.data, 20),
                address=sanitize_input(form.address.data, 500)
            )
            coach.set_password(form.password.data)
            
            db.session.add(coach)
            db.session.commit()
            
            app.logger.info(f'New coach registered: {coach.email}')
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Registration error: {str(e)}')
            flash('Registration failed. Please try again.', 'error')
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'coach_id' in session:
        return redirect(url_for('dashboard'))
        
    form = LoginForm()
    
    if form.validate_on_submit():
        coach = Coach.query.filter_by(email=form.email.data.lower().strip()).first()
        
        if coach and coach.check_password(form.password.data) and coach.is_active:
            session['coach_id'] = coach.id
            session['coach_name'] = coach.name
            session.permanent = True
            
            # Update last login
            coach.last_login = datetime.utcnow()
            db.session.commit()
            
            app.logger.info(f'Coach logged in: {coach.email}')
            flash(f'Welcome back, {coach.name}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            app.logger.warning(f'Failed login attempt: {form.email.data}')
            flash('Invalid email or password.', 'error')
    
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    coach_id = session.get('coach_id')
    session.clear()
    app.logger.info(f'Coach logged out: {coach_id}')
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    coach_id = session['coach_id']
    
    try:
        # Update overdue invoices
        today = datetime.now().date()
        Invoice.query.filter(
            Invoice.coach_id == coach_id,
            Invoice.status == 'pending',
            Invoice.due_date < today
        ).update({'status': 'overdue'})
        db.session.commit()
        
        # Get dashboard statistics
        total_students = Student.query.filter_by(coach_id=coach_id, is_active=True).count()
        
        pending_invoices = Invoice.query.filter_by(coach_id=coach_id, status='pending').count()
        
        total_pending_amount = db.session.query(db.func.sum(Invoice.amount))\
            .filter_by(coach_id=coach_id, status='pending').scalar() or 0
        
        # Recent invoices
        recent_invoices = Invoice.query.filter_by(coach_id=coach_id)\
            .options(db.joinedload(Invoice.student))\
            .order_by(Invoice.created_at.desc())\
            .limit(5).all()
        
        # Overdue invoices
        overdue_invoices = Invoice.query.filter(
            Invoice.coach_id == coach_id,
            Invoice.status == 'overdue'
        ).options(db.joinedload(Invoice.student)).all()
        
        return render_template('dashboard.html',
                             total_students=total_students,
                             pending_invoices=pending_invoices,
                             total_pending_amount=float(total_pending_amount),
                             recent_invoices=recent_invoices,
                             overdue_invoices=overdue_invoices)
                             
    except Exception as e:
        app.logger.error(f'Dashboard error: {str(e)}')
        flash('Error loading dashboard. Please try again.', 'error')
        return render_template('dashboard.html',
                             total_students=0,
                             pending_invoices=0,
                             total_pending_amount=0,
                             recent_invoices=[],
                             overdue_invoices=[])

@app.route('/students')
@login_required
def students():
    coach_id = session['coach_id']
    try:
        students = Student.query.filter_by(coach_id=coach_id, is_active=True)\
            .order_by(Student.name).all()
        return render_template('students.html', students=students)
    except Exception as e:
        app.logger.error(f'Students page error: {str(e)}')
        flash('Error loading students. Please try again.', 'error')
        return render_template('students.html', students=[])

@app.route('/students/add', methods=['GET', 'POST'])
@login_required
def add_student():
    form = StudentForm()
    
    if form.validate_on_submit():
        try:
            student = Student(
                coach_id=session['coach_id'],
                name=sanitize_input(form.name.data, 100),
                email=form.email.data.lower().strip() if form.email.data else None,
                phone=sanitize_input(form.phone.data, 20)
            )
            
            db.session.add(student)
            db.session.commit()
            
            app.logger.info(f'New student added: {student.name} by coach {session["coach_id"]}')
            flash('Student added successfully!', 'success')
            return redirect(url_for('students'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Add student error: {str(e)}')
            flash('Failed to add student. Please try again.', 'error')
    
    return render_template('add_student.html', form=form)

@app.route('/invoices')
@login_required
def invoices():
    coach_id = session['coach_id']
    status_filter = request.args.get('status', 'all')
    
    try:
        query = Invoice.query.filter_by(coach_id=coach_id)\
            .options(db.joinedload(Invoice.student))
        
        if status_filter != 'all':
            query = query.filter_by(status=status_filter)
        
        invoices = query.order_by(Invoice.created_at.desc()).all()
        
        return render_template('invoices.html', invoices=invoices, status_filter=status_filter)
        
    except Exception as e:
        app.logger.error(f'Invoices page error: {str(e)}')
        flash('Error loading invoices. Please try again.', 'error')
        return render_template('invoices.html', invoices=[], status_filter=status_filter)

@app.route('/invoices/create', methods=['GET', 'POST'])
@login_required
def create_invoice():
    form = InvoiceForm()
    coach_id = session['coach_id']
    
    # Populate student choices
    try:
        students = Student.query.filter_by(coach_id=coach_id, is_active=True)\
            .order_by(Student.name).all()
        form.student_id.choices = [(s.id, s.name) for s in students]
        
        if not students:
            flash('You need to add students before creating invoices.', 'warning')
            return redirect(url_for('add_student'))
        
        # Pre-select student if passed in URL
        student_id = request.args.get('student_id')
        if student_id:
            try:
                student_id = int(student_id)
                if any(s.id == student_id for s in students):
                    form.student_id.data = student_id
            except ValueError:
                pass
        
        if form.validate_on_submit():
            try:
                invoice = Invoice(
                    coach_id=coach_id,
                    student_id=form.student_id.data,
                    amount=form.amount.data,
                    description=sanitize_input(form.description.data, 500),
                    due_date=form.due_date.data
                )
                
                # Generate invoice number
                invoice.invoice_number = invoice.generate_invoice_number(coach_id)
                
                db.session.add(invoice)
                db.session.commit()
                
                app.logger.info(f'Invoice created: {invoice.invoice_number} by coach {coach_id}')
                flash('Invoice created successfully!', 'success')
                return redirect(url_for('invoices'))
                
            except Exception as e:
                db.session.rollback()
                app.logger.error(f'Create invoice error: {str(e)}')
                flash('Failed to create invoice. Please try again.', 'error')
        
        return render_template('create_invoice.html', form=form)
        
    except Exception as e:
        app.logger.error(f'Create invoice page error: {str(e)}')
        flash('Error loading create invoice page. Please try again.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/invoices/<int:invoice_id>/mark_paid', methods=['POST'])
@login_required
def mark_paid(invoice_id):
    try:
        validate_csrf(request.form.get('csrf_token'))
    except:
        flash('Security error. Please try again.', 'error')
        return redirect(url_for('invoices'))
    
    try:
        invoice = Invoice.query.filter_by(
            id=invoice_id, 
            coach_id=session['coach_id']
        ).first()
        
        if not invoice:
            flash('Invoice not found.', 'error')
            return redirect(url_for('invoices'))
        
        if invoice.status != 'paid':
            invoice.status = 'paid'
            invoice.paid_at = datetime.utcnow()
            
            db.session.commit()
            app.logger.info(f'Invoice marked as paid: {invoice.invoice_number}')
            flash('Invoice marked as paid!', 'success')
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Mark paid error: {str(e)}')
        flash('Failed to update invoice. Please try again.', 'error')
    
    return redirect(url_for('invoices'))

@app.route('/api/dashboard_stats')
@login_required
def dashboard_stats():
    """API endpoint for dashboard statistics"""
    coach_id = session['coach_id']
    
    try:
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
        
    except Exception as e:
        app.logger.error(f'Dashboard stats API error: {str(e)}')
        return jsonify({'error': 'Failed to load stats'}), 500

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', 
                         title='Page Not Found', 
                         message='The page you are looking for does not exist.'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    app.logger.error(f'Internal server error: {str(error)}')
    return render_template('error.html',
                         title='Server Error',
                         message='An internal server error occurred. Please try again later.'), 500

@app.errorhandler(403)
def forbidden(error):
    return render_template('error.html',
                         title='Access Forbidden',
                         message='You do not have permission to access this resource.'), 403

@app.errorhandler(400)
def bad_request(error):
    return render_template('error.html',
                         title='Bad Request',
                         message='The request could not be processed.'), 400

# Security headers
@app.after_request
def after_request(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    if not app.debug:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "font-src 'self' https://cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        "connect-src 'self'"
    )
    return response

# Database initialization
def create_tables():
    """Create database tables"""
    with app.app_context():
        db.create_all()
        app.logger.info('Database tables created')

if __name__ == '__main__':
    create_tables()
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    app.run(
        debug=debug_mode,
        host='0.0.0.0',
        port=int(os.environ.get('PORT', 5000))
    )