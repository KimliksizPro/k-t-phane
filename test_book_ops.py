import unittest
from app import app, db, Book, User
from werkzeug.security import generate_password_hash

class BookOpsTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        app.config['WTF_CSRF_ENABLED'] = False
        self.app = app.test_client()
        self.app_context = app.app_context()
        self.app_context.push()
        db.create_all()
        
        # Create admin user if not exists
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(username='admin', password_hash=generate_password_hash('admin'))
            db.session.add(admin)
            db.session.commit()
        
        # Login
        self.app.post('/login', data=dict(
            username='admin',
            password='admin'
        ), follow_redirects=True)

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_add_and_delete_book(self):
        # 1. Add Book
        response = self.app.post('/books/add', data=dict(
            title='Test Book',
            author='Test Author',
            isbn='978-1234567890',
            publication_year='2023',
            publisher='Test Publisher',
            category='Fiction',
            description='Test Description'
        ), follow_redirects=True)
        self.assertIn(b'Test Book', response.data)
        
        book = Book.query.filter_by(isbn='978-1234567890').first()
        self.assertIsNotNone(book)
        
        # 2. Delete Book
        response = self.app.post(f'/books/delete/{book.id}', follow_redirects=True)
        self.assertIn(b'silindi', response.data)
        
        book = Book.query.filter_by(isbn='978-1234567890').first()
        self.assertIsNone(book)

if __name__ == '__main__':
    unittest.main()
