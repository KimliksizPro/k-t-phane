import os
import sqlite3
import psycopg2
from dotenv import load_dotenv

load_dotenv()

SQLITE_DB_PATH = 'library.db'
SUPABASE_URL = os.getenv('DATABASE_URL')

def verify_migration():
    if not SUPABASE_URL:
        print("Error: DATABASE_URL not found.")
        return

    sqlite_conn = sqlite3.connect(SQLITE_DB_PATH)
    sqlite_cursor = sqlite_conn.cursor()
    
    pg_conn = psycopg2.connect(SUPABASE_URL)
    pg_cursor = pg_conn.cursor()
    
    tables = ['user', 'settings', 'student', 'book', 'transaction']
    
    print("\n--- Verification Results ---\n")
    print(f"{'Table':<15} | {'SQLite':<10} | {'Supabase':<10} | {'Status':<10}")
    print("-" * 55)
    
    all_good = True
    
    for table in tables:
        # SQLite count
        sqlite_cursor.execute(f'SELECT COUNT(*) FROM "{table}"')
        sqlite_count = sqlite_cursor.fetchone()[0]
        
        # Supabase count
        pg_cursor.execute(f'SELECT COUNT(*) FROM "{table}"')
        pg_count = pg_cursor.fetchone()[0]
        
        status = "MATCH" if sqlite_count == pg_count else "MISMATCH"
        if status == "MISMATCH":
            all_good = False
            
        print(f"{table:<15} | {sqlite_count:<10} | {pg_count:<10} | {status:<10}")
        
    print("-" * 55)
    if all_good:
        print("\nSUCCESS: All record counts match!")
    else:
        print("\nWARNING: Some record counts do not match.")

    sqlite_conn.close()
    pg_conn.close()

if __name__ == "__main__":
    verify_migration()
