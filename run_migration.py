from app import app, db
from sqlalchemy import text

def migrate():
    with app.app_context():
        print(f"Connected to: {app.config['SQLALCHEMY_DATABASE_URI']}")
        try:
            # Attempt to add the column. 
            # Note: IF usage of SQLite, syntax is slightly different if adding multiple or complex types, 
            # but for a simple BOOLEAN/INTEGER column, standard SQL often works for both or we handle exception.
            
            # Postgres/Standard SQL
            with db.engine.connect() as conn:
                conn.execute(text("ALTER TABLE \"user\" ADD COLUMN device_verification_enabled BOOLEAN DEFAULT TRUE"))
                conn.commit()
            print("Migration successful: Added 'device_verification_enabled' to 'user' table.")
            
        except Exception as e:
            print(f"Migration error (Column might already exist or other issue): {e}")

if __name__ == "__main__":
    migrate()
