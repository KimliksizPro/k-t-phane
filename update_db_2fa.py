
from app import app, db
from sqlalchemy import text, inspect

def update_schema():
    print("Updating database schema...")
    with app.app_context():
        engine = db.engine
        inspector = inspect(engine)
        
        # 1. Update User Table
        with engine.connect() as conn:
            # Check which columns currently exist in 'user' table
            existing_columns = [c['name'] for c in inspector.get_columns('user')]
            
            # Define new columns to add
            # Postgres uses TIMESTAMP, SQLite uses DATETIME (mapped usually). 
            # We use generic SQL types or rely on SQLAlchemy behavior, but raw SQL needs specific types.
            # 'TIMESTAMP' works in both generally for this purpose or we can use generic logic.
            # But let's be specific for Postgres since that's the error.
            
            new_cols = [
                ('session_token', 'VARCHAR(100)'),
                ('last_login_ip', 'VARCHAR(50)'),
                ('last_activity', 'TIMESTAMP'),
                ('allowed_devices', "TEXT DEFAULT '[]'"),
                ('is_locked', 'BOOLEAN DEFAULT FALSE')
            ]

            for col_name, col_type in new_cols:
                if col_name not in existing_columns:
                    print(f"Adding '{col_name}' to User table...")
                    try:
                        # logical branching for sqlite vs postgres syntax if needed, 
                        # but ADD COLUMN is standard. 
                        # 'user' is reserved in Postgres, must be quoted.
                        sql = f'ALTER TABLE "user" ADD COLUMN {col_name} {col_type}'
                        conn.execute(text(sql))
                        conn.commit()
                        print(f" - Added {col_name}")
                    except Exception as e:
                        print(f"Error adding {col_name}: {e}")
                        conn.rollback()
                else:
                    print(f"Column '{col_name}' already exists.")

        # 2. Create LoginRequest Table
        # verify if table exists
        if 'login_request' not in inspector.get_table_names():
            print("Creating 'login_request' table...")
            db.create_all()
            print("Tables created.")
        else:
            print("'login_request' table already exists.")

    print("Schema update completed.")

if __name__ == "__main__":
    update_schema()
