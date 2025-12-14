import sqlite3
import os

databases = ['library.db', 'instance/library.db']

indexes = [
    "CREATE INDEX IF NOT EXISTS idx_student_search ON student (name, surname, school_number)",
    "CREATE INDEX IF NOT EXISTS idx_book_search ON book (title, author, isbn)",
    "CREATE INDEX IF NOT EXISTS idx_book_availability ON book (is_available)",
    "CREATE INDEX IF NOT EXISTS idx_transaction_status ON `transaction` (status)",
    "CREATE INDEX IF NOT EXISTS idx_transaction_dates ON `transaction` (issue_date, due_date)"
]

def apply_indexes():
    found = False
    for db_path in databases:
        if os.path.exists(db_path):
            found = True
            print(f"Applying indexes to {db_path}...")
            try:
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                for idx_sql in indexes:
                    try:
                        cursor.execute(idx_sql)
                        print(f"Executed: {idx_sql}")
                    except Exception as e:
                        print(f"Failed to execute {idx_sql}: {e}")
                
                # Optimize DB size
                print("Optimizing database (VACUUM)...")
                cursor.execute("VACUUM")
                
                conn.commit()
                conn.close()
                print("Done.")
            except Exception as e:
                print(f"Error accessing {db_path}: {e}")
    
    if not found:
        print("No database found to update.")

if __name__ == "__main__":
    apply_indexes()
