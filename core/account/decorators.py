from functools import wraps
from django.core.cache import cache
from rest_framework.response import Response
from rest_framework import status
from .utils import is_phone_number_blocked


def block_phone_number_required(view_func):
    """
    Decorator to block requests from specific phone numbers by checking the cache.
    """
    @wraps(view_func)
    def _wrapped_view(self, request, *args, **kwargs):
        phone_number = request.data.get('phone_number')
        is_blocked, time_remaining = is_phone_number_blocked(phone_number)

        if is_blocked:
            return Response({'detail': f'This phone number is blocked due to multiple failed attempts. Try again in {time_remaining} minutes.'},
                            status=status.HTTP_403_FORBIDDEN)
        return view_func(self, request, *args, **kwargs)

    return _wrapped_view
