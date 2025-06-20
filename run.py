# run.py - Development Server Runner
from app import app, create_tables
import os

if __name__ == '__main__':
    # Create tables if they don't exist
    create_tables()
    
    # Run the development server
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    app.run(
        debug=debug_mode,
        host='0.0.0.0',  # Allow external connections
        port=int(os.environ.get('PORT', 5000))
    )
