"""
SecureTrack Database Initialization Script
Creates the database, tables, and seeds default users with hashed passwords.
"""
import pymysql
import os
import sys
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv

# Load environment
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'))

MYSQL_HOST = os.environ.get('MYSQL_HOST', '127.0.0.1')
MYSQL_PORT = int(os.environ.get('MYSQL_PORT', 3306))
MYSQL_USER = os.environ.get('MYSQL_USER', 'root')
MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD', '')
MYSQL_DB = os.environ.get('MYSQL_DATABASE', 'securetrack')


def init_database():
    """Initialize the SecureTrack database."""
    print("=" * 50)
    print("  SecureTrack Database Initialization")
    print("=" * 50)

    # Step 1: Connect to MySQL server (without database)
    try:
        print(f"\n[1/4] Connecting to MySQL at {MYSQL_HOST}:{MYSQL_PORT}...")
        conn = pymysql.connect(
            host=MYSQL_HOST,
            port=MYSQL_PORT,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            charset='utf8mb4'
        )
        print("      Connected successfully!")
    except pymysql.Error as err:
        print(f"      ERROR: Cannot connect to MySQL: {err}")
        print(f"      Make sure MySQL is running and credentials are correct.")
        sys.exit(1)

    # Step 2: Execute schema.sql
    try:
        print(f"\n[2/4] Executing schema.sql...")
        cursor = conn.cursor()

        schema_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'schema.sql')
        with open(schema_path, 'r', encoding='utf-8') as f:
            schema_sql = f.read()

        # Split by semicolons and execute each statement
        statements = [s.strip() for s in schema_sql.split(';') if s.strip()]
        for stmt in statements:
            # Skip comments-only statements
            lines = [l for l in stmt.split('\n') if l.strip() and not l.strip().startswith('--')]
            if lines:
                try:
                    cursor.execute(stmt)
                except pymysql.Error as e:
                    print(f"      Warning: {e}")

        conn.commit()
        print("      Schema executed successfully!")
    except Exception as err:
        print(f"      ERROR: {err}")
        sys.exit(1)

    # Step 3: Switch to database
    try:
        print(f"\n[3/4] Switching to database '{MYSQL_DB}'...")
        cursor.execute(f"USE `{MYSQL_DB}`")
        print("      Database selected!")
    except pymysql.Error as err:
        print(f"      ERROR: {err}")
        sys.exit(1)

    # Step 4: Seed default users
    try:
        print(f"\n[4/4] Seeding default users...")

        # Check if admin already exists
        cursor.execute("SELECT COUNT(*) as cnt FROM users WHERE email = %s", ('admin@securetrack.local',))
        result = cursor.fetchone()

        if result[0] == 0:
            admin_hash = generate_password_hash('admin123')
            tp_hash = generate_password_hash('user123')

            cursor.execute(
                "INSERT INTO users (username, email, password_hash, role, status) VALUES (%s, %s, %s, %s, %s)",
                ('admin', 'admin@securetrack.local', admin_hash, 'Administrator', 'Active')
            )
            print("      Created: Admin User (admin@securetrack.local / admin123)")

            cursor.execute(
                "INSERT INTO users (username, email, password_hash, role, status) VALUES (%s, %s, %s, %s, %s)",
                ('thirdparty01', 'thirdparty@securetrack.local', tp_hash, 'Third-Party User', 'Active')
            )
            print("      Created: Third-Party User (thirdparty@securetrack.local / user123)")

            conn.commit()
        else:
            print("      Users already exist. Skipping seed.")

    except pymysql.Error as err:
        print(f"      ERROR: {err}")
        sys.exit(1)

    # Create SecureFiles folder
    secure_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'SecureFiles')
    os.makedirs(secure_folder, exist_ok=True)
    print(f"\n      SecureFiles folder: {secure_folder}")

    cursor.close()
    conn.close()

    print("\n" + "=" * 50)
    print("  Database initialization complete!")
    print("=" * 50)
    print("\n  Default credentials:")
    print("  Admin:       admin@securetrack.local / admin123")
    print("  Third-Party: thirdparty@securetrack.local / user123")
    print()


if __name__ == '__main__':
    init_database()
