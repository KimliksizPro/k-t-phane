import unittest
from app import app, db, Student, Book, User
from werkzeug.security import generate_password_hash

class EditOpsTestCase(unittest.TestCase):
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

    def test_edit_student(self):
        # 1. Add Student
        student = Student(name='OldName', surname='OldSurname', school_number='111', class_name='9-A')
        db.session.add(student)
        db.session.commit()
        
        # 2. Edit Student
        response = self.app.post(f'/students/edit/{student.id}', data=dict(
            name='NewName',
            surname='NewSurname',
            school_number='111',
            class_name='9-B'
        ), follow_redirects=True)
        
        self.assertIn(b'NewName', response.data)
        updated_student = Student.query.get(student.id)
        self.assertEqual(updated_student.name, 'NewName')
        self.assertEqual(updated_student.class_name, '9-B')

    def test_edit_book(self):
        # 1. Add Book
        book = Book(title='OldTitle', author='OldAuthor', isbn='999', publication_year='2020')
        db.session.add(book)
        db.session.commit()
        
        # 2. Edit Book
        response = self.app.post(f'/books/edit/{book.id}', data=dict(
            title='NewTitle',
            author='NewAuthor',
            isbn='999',
            publication_year='2021'
        ), follow_redirects=True)
        
        self.assertIn(b'NewTitle', response.data)
        updated_book = Book.query.get(book.id)
        self.assertEqual(updated_book.title, 'NewTitle')
        self.assertEqual(updated_book.publication_year, 2021)

if __name__ == '__main__':
    unittest.main()
