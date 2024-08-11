from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
import re


def validate_phone_number(value):
    """
    Validate that the phone number is 11 digits and starts with '09'.
    """
    if not re.match(r'^09\d{9}$', value):
        raise ValidationError(
            _('Phone number must be exactly 11 digits and start with "09".'))
