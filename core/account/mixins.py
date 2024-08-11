class ClientIPMixin:
    def get_client_ip(self, request):
        """
        Get the client's IP address from the request, preferring 'HTTP_X_FORWARDED_FOR'
        if available, otherwise falling back to 'REMOTE_ADDR'.
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        return x_forwarded_for.split(',')[0].strip() if x_forwarded_for else request.META.get('REMOTE_ADDR')
