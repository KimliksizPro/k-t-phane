from app import app, db, Transaction

with app.app_context():
    active_count = Transaction.query.filter_by(status='active').count()
    print(f"Active Loans: {active_count}")
    
    loans = Transaction.query.filter_by(status='active').all()
    for l in loans:
        print(f"Loan: {l.student.name} - {l.due_date}")
