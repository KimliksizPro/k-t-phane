import unittest
from app import app, db, Student, User
from werkzeug.security import generate_password_hash

class StudentOpsTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF for testing
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

    def test_add_and_delete_student(self):
        # 1. Add Student
        response = self.app.post('/students/add', data=dict(
            name='Test',
            surname='Student',
            school_number='12345',
            class_name='10-A'
        ), follow_redirects=True)
        self.assertIn(b'Test Student', response.data)
        
        student = Student.query.filter_by(school_number='12345').first()
        self.assertIsNotNone(student)
        
        # 2. Delete Student
        response = self.app.post(f'/students/delete/{student.id}', follow_redirects=True)
        self.assertIn(b'silindi', response.data)
        
        student = Student.query.filter_by(school_number='12345').first()
        self.assertIsNone(student)

if __name__ == '__main__':
    unittest.main()
