import re

from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _


def validate_email(data):
    if not re.fullmatch(r'[a-zA-Z\d]{5,50}@gmail.com', data):
        raise ValidationError(
            _('%(value)s email is invalid'),
            params={'value': data},
        )
