import sqlite3
import os

db_path = r"C:\Users\kwame\RMS\instance\revenue_management.db"
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Check table structure
cursor.execute("PRAGMA table_info(user)")
columns = [row[1] for row in cursor.fetchall()]

# Add phone_number column
if "phone_number" not in columns:
    cursor.execute("ALTER TABLE user ADD COLUMN phone_number VARCHAR(20)")
    print("✅ Added phone_number column")
else:
    print("✅ phone_number already exists")

# Add is_temp_password column
if "is_temp_password" not in columns:
    cursor.execute("ALTER TABLE user ADD COLUMN is_temp_password BOOLEAN DEFAULT 0")
    print("✅ Added is_temp_password column")
else:
    print("✅ is_temp_password already exists")

# Update existing records
cursor.execute("UPDATE user SET phone_number = '' WHERE phone_number IS NULL")
cursor.execute("UPDATE user SET is_temp_password = 0 WHERE is_temp_password IS NULL")

# Delete problematic migration file
bad_migration = r"C:\Users\kwame\RMS\migrations\versions\177a6e1cb676_add_phone_number.py"
if os.path.exists(bad_migration):
    os.remove(bad_migration)
    print("✅ Deleted problematic migration file")

conn.commit()
conn.close()

print("✅ User table updated successfully")
