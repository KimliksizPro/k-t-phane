import unittest
from app import app

class StaticTestCase(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()

    def test_custom_css(self):
        response = self.app.get('/static/css/custom.css')
        print(f"custom.css status: {response.status_code}")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'body', response.data)

    def test_bootstrap_css(self):
        response = self.app.get('/static/css/bootstrap.min.css')
        print(f"bootstrap.min.css status: {response.status_code}")
        self.assertEqual(response.status_code, 200)

if __name__ == '__main__':
    unittest.main()
