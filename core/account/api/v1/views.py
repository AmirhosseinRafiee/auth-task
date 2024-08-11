from rest_framework.generics import GenericAPIView, RetrieveUpdateAPIView, UpdateAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.core.cache import cache
from django.utils.translation import gettext_lazy as _
from ...serializers import (
    LoginSerializer,
    LoginOTPSerializer,
    UserDetailSerializer,
    LoginPasswordSerializer,
    SetPasswordSerializer,
    ResetPasswordSerializer,
    OTPForDevSerializer,
)
from ...pemissions import IsNotAuthenticated
import random
import string

User = get_user_model()


class LoginAPIView(GenericAPIView):
    """
    View to handle user login with phone number.
    If the user has a password set, redirect to password login.
    Otherwise, generate an OTP and return a nonce for verification.
    """
    serializer_class = LoginSerializer
    permission_classes = [IsNotAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        phone_number = serializer.validated_data['phone_number']

        if self._user_exists_and_has_password(phone_number):
            return Response({'phone_number': phone_number, 'redirect_to': reverse('account:login-password')})

        # Generate a unique nonce and OTP code
        nonce = ''.join(random.choices(
            string.ascii_letters + string.digits, k=16))
        otp_code = ''.join(random.choices(string.digits, k=6))

        # Save phone number and OTP code to the cache with the nonce as the key
        cache.set(nonce, {
            'phone_number': phone_number,
            'otp_code': otp_code
        }, timeout=300)  # Cache timeout in seconds

        return Response({'nonce': nonce, 'redirect_to': reverse('account:login-otp')})

    def _user_exists_and_has_password(self, phone_number):
        """
        Check if a user with the given phone number exists and has a usable password.
        """
        user = User.objects.filter(phone_number=phone_number).first()
        return user and user.has_usable_password()


class LoginPasswordAPIView(GenericAPIView):
    """
    View to handle login with phone number and password.
    """
    serializer_class = LoginPasswordSerializer
    permission_classes = [IsNotAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']

        # Generate or retrieve the authentication token for the user
        token, created = Token.objects.get_or_create(user=user)
        return Response({
            'token': token.key,
            'user': UserDetailSerializer(user).data,
            'detail': _('Login successful.')
        }, status=status.HTTP_200_OK)


class LoginOTPAPIView(GenericAPIView):
    """
    View to handle OTP verification.
    """
    serializer_class = LoginOTPSerializer
    permission_classes = [IsNotAuthenticated]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        phone_number = serializer.validated_data['phone_number']

        # Delete the nonce from the cache after successful validation
        cache.delete(serializer.validated_data['nonce'])

        # Find or create the user associated with the phone number
        user = User.objects.filter(phone_number=phone_number).first()
        if user is None:
            # Create a new user if not found
            user = User.objects.create_user(phone_number=phone_number)
            status_code = status.HTTP_201_CREATED
            msg = _(
                'OTP verified successfully. A new user has been created and authenticated.')
        else:
            status_code = status.HTTP_200_OK
            msg = _('OTP verified successfully. User has been authenticated.')

        # Generate or retrieve the authentication token for the user
        token, created = Token.objects.get_or_create(user=user)

        return Response({
            'token': token.key,
            'user': UserDetailSerializer(user).data,
            'detail': msg
        }, status=status_code)


class UserRetrieveUpdateAPIView(RetrieveUpdateAPIView):
    """
    View for retrieving and updating the current user's details.
    """
    serializer_class = UserDetailSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        """
        Returns the user object that is being retrieved or updated.
        In this case, it's the currently authenticated user.
        """
        return self.request.user


class SetPasswordAPIView(GenericAPIView):
    """
    View for setting the password after OTP verification.
    """
    serializer_class = SetPasswordSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        """
        Returns the user object that is being updated. In this case, it's the currently authenticated user.
        """
        return self.request.user

    def put(self, request, *args, **kwargs):
        """
        Handle PUT requests to set the user's password.
        """
        user = self.get_object()
        serializer = self.get_serializer(
            data=request.data, context={'user': user})
        serializer.is_valid(raise_exception=True)
        new_password = serializer.validated_data['new_password']

        # Set the new password
        user.set_password(new_password)
        user.save()

        return Response({'detail': 'Password has been successfully set.'}, status=status.HTTP_200_OK)


class ResetPasswordAPIView(GenericAPIView):
    """
    API View to allow users to reset their password.
    """
    serializer_class = ResetPasswordSerializer
    permission_classes = [IsAuthenticated]  # User must be authenticated

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response({"detail": _("Password has been reset successfully.")}, status=status.HTTP_200_OK)


class DevOTPAPIView(GenericAPIView):
    """
    View for development purposes to retrieve OTP code by nonce.
    """
    serializer_class = OTPForDevSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        nonce = serializer.validated_data['nonce']

        # Retrieve the OTP code from the cache
        nonce_obj = cache.get(nonce)
        if nonce_obj is None:
            return Response({'detail': 'Invalid or expired nonce.'}, status=status.HTTP_400_BAD_REQUEST)

        otp_code = nonce_obj.get('otp_code')

        return Response({'code': otp_code})
