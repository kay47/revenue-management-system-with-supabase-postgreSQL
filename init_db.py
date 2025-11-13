"""
Database initialization script
Run this after deploying to create tables and admin user
"""
from app import app, db, User
from flask_migrate import upgrade

def init_database():
    """Initialize database tables and create default admin"""
    with app.app_context():
        # Run migrations to create tables
        print("Creating database tables...")
        upgrade()
        
        # Create default admin if no users exist
        if User.query.count() == 0:
            print("Creating default admin user...")
            admin = User(
                username='admin',
                email='admin@example.com',
                phone_number='0000000000',
                role='admin',
                is_temp_password=False
            )
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print('✅ Default admin user created: username=admin, password=admin123')
        else:
            print(f"✅ Database already has {User.query.count()} user(s)")

if __name__ == '__main__':
    init_database()