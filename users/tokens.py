from django.contrib.auth.tokens import PasswordResetTokenGenerator
import six
from .models import user
class TokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return (
            six.text_type(user.email) + six.text_type(timestamp) +
            six.text_type(user.isActive)
        )
account_activation_token = TokenGenerator()