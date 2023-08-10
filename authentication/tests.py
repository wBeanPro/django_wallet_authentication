from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model
from eth_account import Account
from eth_account.messages import encode_defunct

User = get_user_model()

class WalletAddressAuthenticationViewTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.url = reverse('wallet_address_auth')  # Update with your URL name

    def test_wallet_address_authentication_success(self):
        # Create a user with a wallet address
        wallet_address = '0x1234567890abcdef'
        user = User.objects.create(wallet_address=wallet_address)

        # Send a POST request with the wallet address
        response = self.client.post(self.url, {'wallet_address': wallet_address})

        # Assert the response
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['message'], 'Authentication successful')
        self.assertIn('challenge', response.data)
        self.assertTrue('challenge_expiry' in self.client.session)

class VerifySignatureTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.url = reverse('verify_signature')  # Update with your URL name

    def test_verify_signature_success(self):
        # Create a user with a wallet address
        wallet_address = '0x1234567890abcdef'
        private_key = '3f6b94847eee8dbf3144a301ba56c9be832e079f5b4edd69598114229780cf3a'
        # Set up the challenge and session data
        challenge = 'test_challenge'
        self.client.session['challenge'] = challenge
        self.client.session['challenge_expiry'] = 9999999999

        # Generate a valid signature for the challenge
        message = encode_defunct(challenge.encode())
        signed_message = Account.sign_message(message, private_key=private_key)

        # Send a POST request with the signed message and wallet address
        response = self.client.post(self.url, {'signed_message': signed_message.signature.hex(), 'wallet_address': wallet_address})

        # Assert the response
        self.assertEqual(response.status_code, 200)
        self.assertIn('token', response.data)

    def test_verify_signature_invalid_signature(self):
        # Set up the challenge and session data
        challenge = 'test_challenge'
        self.client.session['challenge'] = challenge
        self.client.session['challenge_expiry'] = 9999999999

        # Send a POST request with an invalid signed message and wallet address
        response = self.client.post(self.url, {'signed_message': 'invalid_signature', 'wallet_address': '0x1234567890abcdef'})

        # Assert the response
        self.assertEqual(response.status_code, 200)
        self.assertIn('error', response.data)