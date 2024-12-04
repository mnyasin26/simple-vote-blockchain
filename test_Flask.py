import unittest
import json
from Flask import app, blockchain
from User import User
from Vote import Vote

class FlaskTestCase(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    def test_index(self):
        response = self.app.get('/')
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data['message'], "Hello, World!")

    def test_get_chain(self):
        response = self.app.get('/chain')
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(response.status_code, 200)
        self.assertIn('length', data)
        self.assertIn('chain', data)

    def test_get_unconfirmed_transactions(self):
        response = self.app.get('/unconfirmed_transactions')
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(response.status_code, 200)
        self.assertIn('unconfirmed_transactions', data)

    def test_mine_no_transactions(self):
        response = self.app.get('/mine')
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data['message'], "No transactions to mine")

    def test_add_transaction(self):
        transaction_data = {'transaction': 'sample_transaction'}
        response = self.app.post('/add_transaction', data=json.dumps(transaction_data), content_type='application/json')
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(response.status_code, 201)
        self.assertEqual(data['message'], "Transaction added successfully")

    def test_register_user(self):
        user_data = {'username': 'testuser', 'password': 'testpass'}
        response = self.app.post('/register', data=json.dumps(user_data), content_type='application/json')
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data['message'], "User registered successfully")

    def test_vote(self):
        user_data = {'username': 'testuser', 'password': 'testpass', 'candidate_id': 'candidate1'}
        response = self.app.post('/vote', data=json.dumps(user_data), content_type='application/json')
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(response.status_code, 400)  # Assuming user does not exist in the test database

    def test_validate_vote(self):
        vote_data = {'vote': 'sample_vote'}
        response = self.app.post('/validate_vote', data=json.dumps(vote_data), content_type='application/json')
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(response.status_code, 200)
        self.assertIn('result', data)

    def test_calculate_votes(self):
        response = self.app.get('/calculate_votes')
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(data, dict)

if __name__ == '__main__':
    unittest.main()