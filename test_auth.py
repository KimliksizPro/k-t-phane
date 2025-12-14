import unittest
from app import app, db, User
from flask import url_for

class AuthTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app = app.test_client()
        self.app_context = app.app_context()
        self.app_context.push()
        db.create_all()
        
        # Create a test user
        user = User(username='testadmin')
        user.set_password('testpass')
        db.session.add(user)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_login_page_loads(self):
        response = self.app.get('/login')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Kullan\xc4\xb1c\xc4\xb1 Ad\xc4\xb1', response.data) # Check for "Kullanıcı Adı"
        self.assertIn(b'bootstrap.min.css', response.data) # Check for CSS link
        self.assertIn(b'custom.css', response.data) # Check for Custom CSS link

    def test_login_success(self):
        response = self.app.post('/login', data=dict(
            username='testadmin',
            password='testpass'
        ), follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Genel Bak\xc4\xb1\xc5\x9f', response.data) # Check for "Genel Bakış" (Dashboard title)
        self.assertIn(b'sidebar', response.data) # Check for new sidebar class

    def test_login_failure(self):
        response = self.app.post('/login', data=dict(
            username='testadmin',
            password='wrongpassword'
        ), follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Giri\xc5\x9f ba\xc5\x9far\xc4\xb1s\xc4\xb1z', response.data) # Check for failure message

    def test_logout(self):
        self.app.post('/login', data=dict(
            username='testadmin',
            password='testpass'
        ), follow_redirects=True)
        response = self.app.get('/logout', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'G\xc4\xb0R\xc4\xb0\xc5\x9e YAP', response.data)

    def test_dashboard_access_denied(self):
        response = self.app.get('/', follow_redirects=True)
        self.assertIn(b'G\xc4\xb0R\xc4\xb0\xc5\x9e YAP', response.data)

if __name__ == '__main__':
    unittest.main()
