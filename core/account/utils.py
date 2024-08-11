from django.core.cache import cache
from django.utils import timezone
from datetime import timedelta


def record_failed_attempt(ip_address=None, phone_number=None):
    """
    Record a failed attempt and block IP or phone number if attempts exceed the limit.
    """
    def record_attempt(key_prefix, key_value):
        key = f'{key_prefix}_{key_value}'
        attempts = cache.get(key, [])

        # Filter out old attempts (older than 1 hour)
        one_hour_ago = timezone.now() - timedelta(hours=1)
        recent_attempts = [
            attempt for attempt in attempts if attempt >= one_hour_ago]

        # Record new attempt
        recent_attempts.append(timezone.now())
        cache.set(key, recent_attempts, timeout=3600)  # Cache timeout (1 hour)

        return len(recent_attempts)

    def block_entity(entity_type, entity_value):
        block_key = f'blocked_{entity_type}_{entity_value}'
        block_duration = 3600  # Block for 1 hour
        expiration_time = timezone.now() + timedelta(seconds=block_duration)
        cache.set(block_key, expiration_time, timeout=block_duration)

    # Process IP address if provided
    if ip_address:
        if record_attempt('attempt', ip_address) >= 3:
            block_entity('ip', ip_address)

    # Process phone number if provided
    if phone_number:
        if record_attempt('attempt', phone_number) >= 3:
            block_entity('phone', phone_number)


def is_entity_blocked(entity_type, entity_value):
    """
    Check if an IP address or phone number is blocked and return the remaining time.
    """
    block_key = f'blocked_{entity_type}_{entity_value}'
    expiration_time = cache.get(block_key)

    if expiration_time:
        remaining_time = (expiration_time - timezone.now()).total_seconds()
        if remaining_time > 0:
            return True, int(remaining_time // 60)  # return in minutes
        else:
            cache.delete(block_key)  # Clean up expired block
            return False, 0
    return False, 0


def is_phone_number_blocked(phone_number):
    """
    Check if a phone number is blocked and return the remaining block time in minutes.
    """
    return is_entity_blocked('phone', phone_number)


def is_ip_blocked(ip_address):
    """
    Check if an IP address is blocked and return the remaining block time in minutes.
    """
    return is_entity_blocked('ip', ip_address)


def get_client_ip(request):
    """
    Get the client's IP address, similar to ClientIPMixin.get_client_ip.
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    return x_forwarded_for.split(',')[0].strip() if x_forwarded_for else request.META.get('REMOTE_ADDR')
