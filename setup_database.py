# setup_database.py - Database Setup Script
from app import app, db, Coach, Student, Invoice
from werkzeug.security import generate_password_hash
import secrets

def setup_database():
    """Initialize the database with tables"""
    with app.app_context():
        # Drop all tables and recreate (use with caution in production)
        db.drop_all()
        db.create_all()
        
        print("Database tables created successfully!")
        
        # Create a demo coach account (optional)
        create_demo = input("Create demo coach account? (y/n): ").lower() == 'y'
        
        if create_demo:
            demo_coach = Coach(
                name="Demo Coach",
                email="demo@tenniscoach.com",
                business_name="Demo Tennis Academy",
                phone="555-123-4567",
                address="123 Tennis Court Lane, Sports City, SC 12345"
            )
            demo_coach.set_password("demopassword123")
            
            db.session.add(demo_coach)
            db.session.commit()
            
            # Add some demo students
            students = [
                Student(coach_id=demo_coach.id, name="Alice Johnson", email="alice@email.com", phone="555-111-1111"),
                Student(coach_id=demo_coach.id, name="Bob Smith", email="bob@email.com", phone="555-222-2222"),
                Student(coach_id=demo_coach.id, name="Carol Davis", email="carol@email.com", phone="555-333-3333")
            ]
            
            for student in students:
                db.session.add(student)
            
            db.session.commit()
            
            print("Demo account created:")
            print("Email: demo@tenniscoach.com")
            print("Password: demopassword123")
            print(f"Added {len(students)} demo students")

if __name__ == "__main__":
    setup_database()