"""
Database Setup Script for Revenue Management System
Run this to properly initialize your database
"""

import os
import sys
import subprocess

def run_command(command, description):
    """Run a shell command and handle errors"""
    print(f"\n{'='*60}")
    print(f"📌 {description}")
    print(f"{'='*60}")
    
    try:
        result = subprocess.run(
            command, 
            shell=True, 
            check=True, 
            capture_output=True, 
            text=True
        )
        print(result.stdout)
        if result.stderr:
            print(result.stderr)
        print(f"✅ {description} - SUCCESS")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} - FAILED")
        print(f"Error: {e.stderr}")
        return False

def check_env_file():
    """Check if .env file exists and is properly configured"""
    print("\n🔍 Checking .env configuration...")
    
    if not os.path.exists('.env'):
        print("⚠️  Warning: .env file not found!")
        print("Creating default .env file for SQLite...")
        
        with open('.env', 'w') as f:
            f.write("""# Database Configuration
# For SQLite (default):
# DATABASE_URL will use sqlite:///revenue_management.db

# For PostgreSQL (uncomment and configure):
# DATABASE_URL=postgresql://username:password@localhost/revenue_db

# Secret Key (change in production)
SECRET_KEY=your-secret-key-change-this-in-production

# SMS Provider Configuration
SMS_PROVIDER=mock
OTP_EXPIRY_MINUTES=5

# Other settings as needed
""")
        print("✅ Created default .env file")
    
    # Read and check configuration
    with open('.env', 'r') as f:
        env_content = f.read()
    
    if 'DATABASE_URL' in env_content and 'postgresql' in env_content:
        # Check if line is commented
        for line in env_content.split('\n'):
            if 'DATABASE_URL' in line and 'postgresql' in line and not line.strip().startswith('#'):
                print("📊 PostgreSQL configuration detected")
                return 'postgresql'
    
    print("📊 SQLite configuration detected (default)")
    return 'sqlite'

def install_dependencies(db_type):
    """Install required packages"""
    print(f"\n📦 Installing dependencies for {db_type}...")
    
    packages = ['flask-migrate']
    
    if db_type == 'postgresql':
        packages.append('psycopg2-binary')
        print("Note: Installing PostgreSQL driver (psycopg2-binary)")
    
    for package in packages:
        if not run_command(
            f"pip install {package}", 
            f"Installing {package}"
        ):
            print(f"\n❌ Failed to install {package}")
            return False
    
    return True

def initialize_database():
    """Initialize Flask-Migrate and create migrations"""
    
    # Step 1: Check if migrations folder exists
    if os.path.exists('migrations'):
        print("\n⚠️  Migrations folder already exists!")
        response = input("Do you want to recreate it? (y/n): ").lower()
        
        if response == 'y':
            import shutil
            shutil.rmtree('migrations')
            print("🗑️  Removed existing migrations folder")
        else:
            print("Skipping migration initialization...")
            return True
    
    # Step 2: Initialize migrations
    if not run_command('flask db init', 'Initializing Flask-Migrate'):
        return False
    
    # Step 3: Create initial migration
    if not run_command(
        'flask db migrate -m "Initial migration"', 
        'Creating initial migration'
    ):
        return False
    
    # Step 4: Apply migration
    if not run_command('flask db upgrade', 'Applying migrations to database'):
        return False
    
    return True

def verify_database():
    """Verify database was created successfully"""
    print("\n🔍 Verifying database setup...")
    
    try:
        # Try to import app and check database
        from app import app, db, User
        
        with app.app_context():
            # Check if tables exist
            user_count = User.query.count()
            print(f"✅ Database verified! Found {user_count} users.")
            
            if user_count == 0:
                print("\n💡 No users found. Creating default admin user...")
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
                print("✅ Default admin user created!")
                print("   Username: admin")
                print("   Password: admin123")
                print("   ⚠️  CHANGE THIS PASSWORD IMMEDIATELY IN PRODUCTION!")
        
        return True
    except Exception as e:
        print(f"❌ Database verification failed: {str(e)}")
        return False

def main():
    """Main setup function"""
    print("""
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║     Revenue Management System - Database Setup            ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
    """)
    
    # Step 1: Check environment configuration
    db_type = check_env_file()
    
    # Step 2: Install dependencies
    if not install_dependencies(db_type):
        print("\n❌ Setup failed during dependency installation")
        sys.exit(1)
    
    # Step 3: Initialize database
    if not initialize_database():
        print("\n❌ Setup failed during database initialization")
        sys.exit(1)
    
    # Step 4: Verify setup
    if not verify_database():
        print("\n⚠️  Setup completed but verification failed")
        print("You may need to manually check the database")
        sys.exit(1)
    
    print("""
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║     ✅ Database Setup Complete!                            ║
║                                                            ║
║     You can now run:                                       ║
║     flask run                                              ║
║                                                            ║
║     Or for development:                                    ║
║     python app.py                                          ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
    """)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n❌ Setup interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Unexpected error: {str(e)}")
        sys.exit(1)