from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_str, force_bytes
from django.utils.http import urlsafe_base64_encode


class PasswordTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return urlsafe_base64_encode(force_bytes(user.id) + force_bytes(user) + force_bytes(timestamp))
    

password_token_generator = PasswordTokenGenerator()