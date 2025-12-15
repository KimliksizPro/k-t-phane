from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class Student(db.Model):
    __table_args__ = (
        db.Index('idx_student_search', 'name', 'surname', 'school_number'),
    )
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    surname = db.Column(db.String(100), nullable=False)
    school_number = db.Column(db.String(20), unique=True, nullable=False)
    class_name = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120))
    phone = db.Column(db.String(20))
    address = db.Column(db.Text)
    transactions = db.relationship('Transaction', backref='student', lazy=True, cascade="all, delete-orphan")

class Book(db.Model):
    __table_args__ = (
        db.Index('idx_book_search', 'title', 'author', 'isbn'),
        db.Index('idx_book_availability', 'is_available'),
    )
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    isbn = db.Column(db.String(20), unique=True, nullable=False)
    category = db.Column(db.String(50))
    publisher = db.Column(db.String(100))
    publication_year = db.Column(db.Integer)
    page_count = db.Column(db.Integer)
    description = db.Column(db.Text)
    is_available = db.Column(db.Boolean, default=True)
    transactions = db.relationship('Transaction', backref='book', lazy=True, cascade="all, delete-orphan")

class Transaction(db.Model):
    __table_args__ = (
        db.Index('idx_transaction_status', 'status'),
        db.Index('idx_transaction_dates', 'issue_date', 'due_date'),
    )
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    issue_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    due_date = db.Column(db.DateTime, nullable=False)
    return_date = db.Column(db.DateTime)
    status = db.Column(db.String(20), default='active') # active, returned

class Settings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    loan_period = db.Column(db.Integer, default=15) # Days
    school_name = db.Column(db.String(100), default='Kütüphane Otomasyonu')
    theme = db.Column(db.String(20), default='blue') # blue, red
    active_watcher_id = db.Column(db.Integer, nullable=True) # ID of the currently active watcher

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    role = db.Column(db.String(20), default='admin') # admin, watcher
    password_hash = db.Column(db.String(255), nullable=False)

    session_token = db.Column(db.String(100), nullable=True)
    last_login_ip = db.Column(db.String(50), nullable=True)
    last_activity = db.Column(db.DateTime, nullable=True)
    allowed_devices = db.Column(db.Text, default='[]') # JSON list of device tokens
    is_locked = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        from werkzeug.security import generate_password_hash
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        from werkzeug.security import check_password_hash
        return check_password_hash(self.password_hash, password)

class LoginRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    request_token = db.Column(db.String(100), unique=True, nullable=False)
    verification_code = db.Column(db.String(10), nullable=False)
    ip_address = db.Column(db.String(50))
    device_info = db.Column(db.String(200))
    status = db.Column(db.String(20), default='pending') # pending, approved, rejected, expired
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    
    user = db.relationship('User', backref=db.backref('login_requests', lazy=True))

class QRLoginRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(100), unique=True, nullable=False)
    status = db.Column(db.String(20), default='pending') # pending, approved, expired, rejected
    user_id = db.Column(db.Integer, nullable=True) # Set when approved
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
