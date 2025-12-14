import os
from sqlalchemy import create_engine, text
from dotenv import load_dotenv

load_dotenv()

database_url = os.getenv('DATABASE_URL')
if not database_url:
    print("Error: DATABASE_URL not found in .env")
    exit(1)

print(f"Connecting to database...")
engine = create_engine(database_url)

try:
    with engine.connect() as connection:
        # Check if column exists
        result = connection.execute(text("SELECT column_name FROM information_schema.columns WHERE table_name='settings' AND column_name='active_watcher_id'"))
        if result.fetchone():
            print("'active_watcher_id' column already exists.")
        else:
            print("Adding 'active_watcher_id' column to 'settings' table...")
            connection.execute(text("ALTER TABLE settings ADD COLUMN active_watcher_id INTEGER"))
            connection.commit()
            print("Successfully added 'active_watcher_id' column.")
            
except Exception as e:
    print(f"Error updating database: {e}")
