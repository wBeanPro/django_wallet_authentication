from django.contrib.auth import get_user_model
from django.contrib.auth.backends import BaseBackend
User = get_user_model()
class WalletAddressAuthBackend(BaseBackend):
    def authenticate(self, request, wallet_address=None):
        try:
            user = User.objects.get(wallet_address=wallet_address)
            return user
        except User.DoesNotExist:
            user = User.objects.create_user(
                wallet_address=wallet_address,
                username=wallet_address,
                password=''
            )
            return user

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

