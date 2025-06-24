# app.py - CoachPay - Invoice Management for Coaches
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, DecimalField, DateField, SelectField, TextAreaField, EmailField, PasswordField
from wtforms.validators import DataRequired, Email, Length, NumberRange
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import secrets
import os
from functools import wraps
import sqlalchemy as sa

# Initialize Flask app
app = Flask(__name__)

# Environment detection
is_development = os.environ.get('FLASK_ENV') == 'development'

# Security Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['WTF_CSRF_TIME_LIMIT'] = 3600

# Set security configs based on environment
if is_development:
    # Development settings - less secure for local testing
    app.config['SESSION_COOKIE_SECURE'] = False
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
else:
    # Production settings - secure
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)

# Database Configuration
database_url = os.environ.get('DATABASE_URL', 'sqlite:///coachpay.db')
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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    invoices = db.relationship('Invoice', backref='coach', lazy=True, cascade='all, delete-orphan')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Invoice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    coach_id = db.Column(db.Integer, db.ForeignKey('coach.id'), nullable=False)
    invoice_number = db.Column(db.String(50), unique=True, nullable=False)
    student_name = db.Column(db.String(100), nullable=False)
    student_email = db.Column(db.String(120))
    date_issued = db.Column(db.Date, nullable=False, default=datetime.utcnow().date())
    due_date = db.Column(db.Date, nullable=False)
    amount = db.Column(sa.Numeric(10, 2), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, paid, overdue
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    paid_at = db.Column(db.DateTime)
    
    def generate_invoice_number(self, coach_id):
        """Generate unique invoice number"""
        today = datetime.now()
        prefix = f"CP-{coach_id}-{today.strftime('%Y%m')}"
        
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

class InvoiceForm(FlaskForm):
    student_name = StringField('Student Name', validators=[DataRequired(), Length(min=2, max=100)])
    student_email = EmailField('Student Email (Optional)', validators=[Email()])
    amount = DecimalField('Amount (£)', validators=[DataRequired(), NumberRange(min=0.01, max=9999.99)])
    description = TextAreaField('Description', validators=[DataRequired(), Length(max=500)])
    due_date = DateField('Due Date', validators=[DataRequired()])

# Simple form for CSRF protection on POST requests
class CSRFForm(FlaskForm):
    pass

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'coach_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

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
        if Coach.query.filter_by(email=form.email.data.lower()).first():
            flash('Email already registered. Please use a different email.', 'error')
            return render_template('register.html', form=form)
        
        coach = Coach(
            name=form.name.data.strip(),
            email=form.email.data.lower()
        )
        coach.set_password(form.password.data)
        
        try:
            db.session.add(coach)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception:
            db.session.rollback()
            flash('Registration failed. Please try again.', 'error')
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    
    if form.validate_on_submit():
        coach = Coach.query.filter_by(email=form.email.data.lower()).first()
        
        if coach and coach.check_password(form.password.data):
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
    
    # Mark overdue invoices first
    today = datetime.now().date()
    Invoice.query.filter(
        Invoice.coach_id == coach_id,
        Invoice.status == 'pending',
        Invoice.due_date < today
    ).update({'status': 'overdue'})
    db.session.commit()
    
    # Get statistics
    total_invoices = Invoice.query.filter_by(coach_id=coach_id).count()
    pending_invoices = Invoice.query.filter_by(coach_id=coach_id, status='pending').count()
    overdue_count = Invoice.query.filter_by(coach_id=coach_id, status='overdue').count()
    total_pending_amount = db.session.query(db.func.sum(Invoice.amount))\
        .filter_by(coach_id=coach_id, status='pending').scalar() or 0
    
    # Recent invoices
    recent_invoices = Invoice.query.filter_by(coach_id=coach_id)\
        .order_by(Invoice.created_at.desc())\
        .limit(5).all()
    
    return render_template('dashboard.html',
                         total_invoices=total_invoices,
                         pending_invoices=pending_invoices,
                         overdue_count=overdue_count,
                         total_pending_amount=total_pending_amount,
                         recent_invoices=recent_invoices)

@app.route('/invoices')
@login_required
def invoices():
    coach_id = session['coach_id']
    status_filter = request.args.get('status', 'all')
    
    # Mark overdue invoices first
    today = datetime.now().date()
    Invoice.query.filter(
        Invoice.coach_id == coach_id,
        Invoice.status == 'pending',
        Invoice.due_date < today
    ).update({'status': 'overdue'})
    db.session.commit()
    
    query = Invoice.query.filter_by(coach_id=coach_id)
    
    if status_filter != 'all':
        query = query.filter_by(status=status_filter)
    
    invoices = query.order_by(Invoice.created_at.desc()).all()
    
    # Create CSRF form for the mark as paid buttons
    csrf_form = CSRFForm()
    
    return render_template('invoices.html', 
                         invoices=invoices, 
                         status_filter=status_filter,
                         csrf_form=csrf_form)

@app.route('/view-invoice/<int:invoice_id>')
@login_required
def view_invoice(invoice_id):
    invoice = Invoice.query.filter_by(
        id=invoice_id, 
        coach_id=session['coach_id']
    ).first_or_404()
    
    csrf_form = CSRFForm()
    
    return render_template('view_invoice.html', invoice=invoice, csrf_form=csrf_form)

@app.route('/create-invoice', methods=['GET', 'POST'])
@login_required
def create_invoice():
    form = InvoiceForm()
    
    if form.validate_on_submit():
        invoice = Invoice(
            coach_id=session['coach_id'],
            student_name=form.student_name.data.strip(),
            student_email=form.student_email.data.lower() if form.student_email.data else None,
            amount=form.amount.data,
            description=form.description.data.strip(),
            due_date=form.due_date.data
        )
        
        invoice.invoice_number = invoice.generate_invoice_number(session['coach_id'])
        
        try:
            db.session.add(invoice)
            db.session.commit()
            flash('Invoice created successfully!', 'success')
            return redirect(url_for('view_invoice', invoice_id=invoice.id))
        except Exception:
            db.session.rollback()
            flash('Failed to create invoice. Please try again.', 'error')
    
    return render_template('create_invoice.html', form=form)

@app.route('/edit-invoice/<int:invoice_id>', methods=['GET', 'POST'])
@login_required
def edit_invoice(invoice_id):
    invoice = Invoice.query.filter_by(
        id=invoice_id, 
        coach_id=session['coach_id']
    ).first_or_404()
    
    form = InvoiceForm(obj=invoice)
    
    if form.validate_on_submit():
        invoice.student_name = form.student_name.data.strip()
        invoice.student_email = form.student_email.data.lower() if form.student_email.data else None
        invoice.amount = form.amount.data
        invoice.description = form.description.data.strip()
        invoice.due_date = form.due_date.data
        
        # Check if we need to update status based on new due date
        today = datetime.now().date()
        if invoice.status == 'pending' and invoice.due_date < today:
            invoice.status = 'overdue'
        elif invoice.status == 'overdue' and invoice.due_date >= today:
            invoice.status = 'pending'
        
        try:
            db.session.commit()
            flash('Invoice updated successfully!', 'success')
            return redirect(url_for('view_invoice', invoice_id=invoice.id))
        except Exception:
            db.session.rollback()
            flash('Failed to update invoice. Please try again.', 'error')
    
    return render_template('edit_invoice.html', form=form, invoice=invoice)

@app.route('/repeat-invoice/<int:invoice_id>')
@login_required
def repeat_invoice(invoice_id):
    original_invoice = Invoice.query.filter_by(
        id=invoice_id, 
        coach_id=session['coach_id']
    ).first_or_404()
    
    # Create a form with the original invoice data
    form = InvoiceForm()
    form.student_name.data = original_invoice.student_name
    form.student_email.data = original_invoice.student_email
    form.amount.data = original_invoice.amount
    form.description.data = original_invoice.description
    # Set due date to 14 days from today by default
    form.due_date.data = datetime.now().date() + timedelta(days=14)
    
    flash(f'Creating new invoice based on {original_invoice.invoice_number}', 'info')
    return render_template('create_invoice.html', form=form)

@app.route('/mark-paid/<int:invoice_id>', methods=['POST'])
@login_required
def mark_paid(invoice_id):
    # Validate CSRF token
    csrf_form = CSRFForm()
    if not csrf_form.validate_on_submit():
        flash('Security token expired. Please try again.', 'error')
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
            flash(f'Invoice {invoice.invoice_number} marked as paid!', 'success')
        except Exception:
            db.session.rollback()
            flash('Failed to update invoice. Please try again.', 'error')
    else:
        flash('Invoice is already marked as paid.', 'info')
    
    # Redirect back to the referring page if possible
    return redirect(request.referrer or url_for('invoices'))

@app.route('/delete-invoice/<int:invoice_id>', methods=['POST'])
@login_required
def delete_invoice(invoice_id):
    # Validate CSRF token
    csrf_form = CSRFForm()
    if not csrf_form.validate_on_submit():
        flash('Security token expired. Please try again.', 'error')
        return redirect(url_for('invoices'))
    
    invoice = Invoice.query.filter_by(
        id=invoice_id, 
        coach_id=session['coach_id']
    ).first_or_404()
    
    invoice_number = invoice.invoice_number
    
    try:
        db.session.delete(invoice)
        db.session.commit()
        flash(f'Invoice {invoice_number} has been deleted.', 'success')
    except Exception:
        db.session.rollback()
        flash('Failed to delete invoice. Please try again.', 'error')
    
    return redirect(url_for('invoices'))

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

# Security headers - conditional based on environment
@app.after_request
def after_request(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Only set HTTPS headers in production
    if not is_development:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    response.headers['Content-Security-Policy'] = ("default-src 'self'; "
                                                   "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                                                   "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
                                                   "font-src 'self' https://cdn.jsdelivr.net https://fonts.gstatic.com; "
                                                   "img-src 'self' data:;")
    return response

# Database initialization
def create_tables():
    with app.app_context():
        db.create_all()

if __name__ == '__main__':
    create_tables()
    app.run(debug=True, host='0.0.0.0', port=5001)  # Changed to port 5001