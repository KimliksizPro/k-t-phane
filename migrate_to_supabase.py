import os
import sqlite3
import psycopg2
from psycopg2.extras import execute_values
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configuration
SQLITE_DB_PATH = 'library.db'
SUPABASE_URL = os.getenv('DATABASE_URL')

def migrate_data():
    if not SUPABASE_URL:
        print("Error: DATABASE_URL not found in .env file.")
        return

    print("Connecting to databases...")
    
    # Connect to SQLite
    try:
        sqlite_conn = sqlite3.connect(SQLITE_DB_PATH)
        sqlite_cursor = sqlite_conn.cursor()
        print("Connected to SQLite.")
    except Exception as e:
        print(f"Error connecting to SQLite: {e}")
        return

    # Connect to PostgreSQL (Supabase)
    try:
        pg_conn = psycopg2.connect(SUPABASE_URL)
        pg_cursor = pg_conn.cursor()
        print("Connected to Supabase PostgreSQL.")
    except Exception as e:
        print(f"Error connecting to Supabase: {e}")
        return

    # Tables to migrate (Order matters due to foreign keys)
    # User, Settings, Student, Book, Transaction
    
    tables = ['user', 'settings', 'student', 'book', 'transaction']
    
    # Mapping for table names if they differ (Flask-SQLAlchemy usually uses lowercase class names)
    # But let's check if tables exist in Postgres first. 
    # Since we are using SQLAlchemy in the app, we should probably let SQLAlchemy create the tables first.
    # But for this script, let's assume tables are created or we create them.
    # Actually, the best way is to run the app once to create tables, or use db.create_all()
    
    print("\n--- Starting Data Migration ---\n")

    for table in tables:
        print(f"Migrating table: {table}...")
        
        # Read from SQLite
        try:
            # Quote table name for SQLite to handle reserved keywords like 'transaction'
            sqlite_cursor.execute(f'SELECT * FROM "{table}"')
            rows = sqlite_cursor.fetchall()
            columns = [description[0] for description in sqlite_cursor.description]
            
            if not rows:
                print(f"No data in SQLite table '{table}'. Skipping.")
                continue
                
            print(f"Found {len(rows)} rows in SQLite table '{table}'.")
            
            # Convert boolean columns (0/1) to True/False for Postgres
            # Check for 'is_available' in columns
            if 'is_available' in columns:
                idx = columns.index('is_available')
                # Convert rows to list of lists to modify
                rows = [list(row) for row in rows]
                for row in rows:
                    row[idx] = bool(row[idx])
            
            # Prepare INSERT statement for Postgres
            # execute_values expects a single %s for the entire row tuple in the template
            
            cols_str = ', '.join([f'"{c}"' for c in columns])
            # The template for execute_values should be just %s, and it expands it to (v1, v2, ...)
            # But we want to be explicit about columns.
            
            query = f'INSERT INTO "{table}" ({cols_str}) VALUES %s ON CONFLICT (id) DO NOTHING'
            
            # Execute batch insert
            execute_values(pg_cursor, query, rows)
            pg_conn.commit()
            print(f"Successfully migrated {len(rows)} rows to Supabase table '{table}'.")
            
            # Update sequence
            # Postgres sequences need to be updated to the max id to avoid conflicts with new inserts
            pg_cursor.execute(f"SELECT setval(pg_get_serial_sequence('\"{table}\"', 'id'), coalesce(max(id),0) + 1, false) FROM \"{table}\";")
            pg_conn.commit()
            print(f"Updated sequence for table '{table}'.")

        except Exception as e:
            print(f"Error migrating table '{table}': {e}")
            pg_conn.rollback()

    print("\n--- Migration Completed ---")
    
    sqlite_conn.close()
    pg_conn.close()

if __name__ == "__main__":
    # First, ensure tables exist in Supabase
    # We can do this by importing the app and running db.create_all()
    # But we need to be careful not to run the app itself.
    
    print("Ensuring tables exist in Supabase...")
    try:
        from app import app, db
        with app.app_context():
            db.create_all()
            print("Tables created (if they didn't exist).")
    except Exception as e:
        print(f"Error creating tables: {e}")
        print("Continuing with migration script, assuming tables might exist...")

    migrate_data()
