from django.shortcuts import render
import jwt
from datetime import datetime, timedelta
from django.conf import settings
import hashlib
import time
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate, login
from authentication.backends import WalletAddressAuthBackend
from eth_account import Account
from eth_account.messages import encode_defunct
User = get_user_model()

class WalletAddressAuthenticationView(APIView):

    def post(self, request):
        wallet_address = request.data.get('wallet_address')
        
        user = authenticate(request, wallet_address=wallet_address)
        
        if user is not None:
            login(request, user)
            challenge = hashlib.sha256(str(time.time()).encode()).hexdigest()
            request.session['challenge'] = challenge
            request.session['challenge_expiry'] = int(time.time()) + 300
            return Response({'message': 'Authentication successful','challenge': challenge}, status=status.HTTP_200_OK)
        
        return Response({'message': 'Invalid wallet address'}, status=status.HTTP_400_BAD_REQUEST)
    
class VerifySignature(APIView):

    def post(self, request):
        challenge = request.session.get('challenge')
        challenge_expiry = request.session.get('challenge_expiry')

        if not challenge or not challenge_expiry:
            return Response({'error': 'Challenge not found or has expired'})

        if int(time.time()) > challenge_expiry:
            return Response({'error': 'Challenge has expired'})
        
        signed_message = request.POST.get('signed_message')
        wallet_address = request.POST.get('wallet_address')
        message_hash = encode_defunct(text=challenge)
        is_valid_signature = Account.recover_message(message_hash, signature=signed_message) == wallet_address

        if is_valid_signature:
            user = User.objects.get(wallet_address=wallet_address)
            token = self.generate_jwt_token(user)
            return Response({'token': token})
        else:
            return Response({'error': 'Invalid signature'})
        
    def generate_jwt_token(user):
        payload = {
            'user_id': user.id,
            'exp': datetime.utcnow() + timedelta(minutes=15),
        }
        token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
        return token.decode('utf-8')