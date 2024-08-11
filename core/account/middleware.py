from django.core.cache import cache
from django.http import JsonResponse
from .utils import get_client_ip, is_ip_blocked


def ip_blocking_middleware(get_response):
    """
    Middleware to block IP addresses that have been blocked due to too many failed attempts.
    """
    def middleware(request):
        ip_address = get_client_ip(request)
        is_blocked, time_remaining = is_ip_blocked(ip_address)

        if is_blocked:
            return JsonResponse({'detail': f'Your IP is blocked due to too many failed attempts. Try again in {time_remaining} minutes.'}, status=403)

        response = get_response(request)
        return response

    return middleware
