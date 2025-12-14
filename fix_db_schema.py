import os
import psycopg2
from dotenv import load_dotenv

load_dotenv()

SUPABASE_URL = os.getenv('DATABASE_URL')

def fix_schema():
    if not SUPABASE_URL:
        print("Error: DATABASE_URL not found.")
        return

    try:
        conn = psycopg2.connect(SUPABASE_URL)
        cursor = conn.cursor()
        
        print("Altering 'user' table to increase password_hash length...")
        cursor.execute('ALTER TABLE "user" ALTER COLUMN password_hash TYPE VARCHAR(255);')
        conn.commit()
        print("Successfully altered table.")
        
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    fix_schema()
