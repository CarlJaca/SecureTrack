"""
SecureTrack Database Module
Uses PyMySQL with DictCursor for all database operations.
"""
import pymysql
import pymysql.cursors
from config import Config


def get_db_connection():
    """Create and return a new database connection."""
    try:
        connection = pymysql.connect(
            host=Config.MYSQL_HOST,
            port=Config.MYSQL_PORT,
            user=Config.MYSQL_USER,
            password=Config.MYSQL_PASSWORD,
            database=Config.MYSQL_DB,
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=False,
            charset='utf8mb4'
        )
        return connection
    except pymysql.Error as err:
        print(f"[DB] Connection error: {err}")
        return None


def fetch_all(query, params=None):
    """Execute a SELECT query and return all matching rows as a list of dicts."""
    conn = get_db_connection()
    if not conn:
        return []
    try:
        with conn.cursor() as cursor:
            cursor.execute(query, params or ())
            result = cursor.fetchall()
        return result
    except pymysql.Error as err:
        print(f"[DB] Query error: {err}")
        return []
    finally:
        conn.close()


def fetch_one(query, params=None):
    """Execute a SELECT query and return a single row as a dict."""
    conn = get_db_connection()
    if not conn:
        return None
    try:
        with conn.cursor() as cursor:
            cursor.execute(query, params or ())
            result = cursor.fetchone()
        return result
    except pymysql.Error as err:
        print(f"[DB] Query error: {err}")
        return None
    finally:
        conn.close()


def execute_query(query, params=None):
    """Execute an INSERT/UPDATE/DELETE query. Returns lastrowid for INSERT, True for others, False on error."""
    conn = get_db_connection()
    if not conn:
        return False
    try:
        with conn.cursor() as cursor:
            cursor.execute(query, params or ())
            conn.commit()
            last_id = cursor.lastrowid
            return last_id if last_id else True
    except pymysql.Error as err:
        print(f"[DB] Execute error: {err}")
        conn.rollback()
        return False
    finally:
        conn.close()
