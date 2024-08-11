from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
import re


def validate_phone_number(value):
    pattern = r'^09\d{9}$'
    if not re.match(pattern, value):
        raise ValidationError(
            _('Phone number must be exactly 11 digits and start with "09".'),
            params={'value': value},
        )
