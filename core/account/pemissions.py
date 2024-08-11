from rest_framework.permissions import BasePermission

class IsNotAuthenticated(BasePermission):
    """
    Custom permission to check that the user is not authenticated.
    """
    def has_permission(self, request, view):
        # Allow access if the user is not authenticated
        return not request.user.is_authenticated
