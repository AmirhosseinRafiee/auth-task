from rest_framework import serializers
from django.core.validators import RegexValidator
from django.core.exceptions import ValidationError
from django.core.cache import cache
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth import authenticate, get_user_model
from django.utils.translation import gettext_lazy as _
from .validations import validate_phone_number
from .utils import is_phone_number_blocked

User = get_user_model()


class LoginSerializer(serializers.Serializer):
    """
    Serializer for logging in users via phone number.
    """
    phone_number = serializers.CharField(
        max_length=11,
        validators=[validate_phone_number]
    )


class LoginPasswordSerializer(serializers.Serializer):
    """
    Serializer for logging in users with phone number and password.
    """
    phone_number = serializers.CharField(
        max_length=11,
        validators=[validate_phone_number]
    )
    password = serializers.CharField(
        write_only=True,  # Ensure the password is not included in the serialized output
    )

    def validate(self, attrs):
        """
        Validate the provided phone number and password.
        """
        phone_number = attrs.get('phone_number')
        password = attrs.get('password')

        # Ensure both phone number and password are provided
        if not (phone_number and password):
            msg = _('Must include "phone_number" and "password".')
            raise serializers.ValidationError(msg, code='authorization')

        # Authenticate the user with the provided credentials
        user = authenticate(
            request=self.context.get('request'),
            username=phone_number,
            password=password
        )

        # Raise error if authentication fails
        if not user:
            msg = _('Unable to log in with provided credentials.')
            raise serializers.ValidationError(msg, code='authorization')

        attrs['user'] = user
        return attrs


class LoginOTPSerializer(serializers.Serializer):
    """
    Serializer for verifying OTP codes.
    """
    nonce = serializers.CharField(
        max_length=16,
        min_length=16,
        error_messages={
            'max_length': _('Nonce must be exactly 16 characters long.'),
            'min_length': _('Nonce must be exactly 16 characters long.')
        }
    )
    code = serializers.CharField(
        validators=[
            RegexValidator(
                regex=r'^\d{6}$',
                message=_('Code must be exactly 6 digits.')
            )
        ],
    )

    def validate(self, attrs):
        """
        Validate the provided nonce and OTP code.
        """
        nonce = attrs.get('nonce')
        code = attrs.get('code')

        # Retrieve the nonce value from the cache
        nonce_val = cache.get(nonce)

        # Store phone_number in the serializer instance for later access
        self.phone_number = nonce_val.get(
            'phone_number') if nonce_val else None

        # Raise error if nonce is invalid or expired
        if nonce_val is None:
            msg = _('Invalid or expired nonce.')
            raise serializers.ValidationError(msg)

        # Check if the phone number is blocked
        is_blocked, time_remaining = is_phone_number_blocked(self.phone_number)
        if is_blocked:
            raise serializers.ValidationError(
                _('This phone number is blocked due to multiple failed attempts. Try again in {time_remaining} minutes.').format(
                    time_remaining=time_remaining)
            )

        attrs['phone_number'] = nonce_val.get('phone_number')
        attrs['otp_code'] = nonce_val.get('otp_code')

        # Validate the OTP code
        if attrs['otp_code'] != code:
            msg = _('Invalid OTP code.')
            raise serializers.ValidationError(msg)

        return super().validate(attrs)


class UserDetailSerializer(serializers.ModelSerializer):
    """
    Serializer for retrieving user details.
    """
    class Meta:
        model = User
        fields = ['id', 'phone_number', 'first_name', 'last_name', 'email']
        read_only_fields = ['id', 'phone_number']


class SetPasswordSerializer(serializers.Serializer):
    """
    Serializer for setting a new password for the user.
    """
    new_password = serializers.CharField(
        style={'input_type': 'password'},
        trim_whitespace=False
    )
    confirm_password = serializers.CharField(
        style={'input_type': 'password'},
        trim_whitespace=False
    )

    def validate_new_password(self, value):
        """
        Validate the new password using Django's built-in validators.
        """
        try:
            validate_password(value)
        except ValidationError as e:
            raise serializers.ValidationError(e.messages)
        return value

    def validate(self, attrs):
        """
        Ensure that the new password and confirm password match.
        """
        new_password = attrs.get('new_password')
        confirm_password = attrs.get('confirm_password')

        if new_password != confirm_password:
            raise serializers.ValidationError(
                {"confirm_password": "Passwords do not match."})

        # Additional validation to check if the user has already set a password
        user = self.context.get('user')
        if user and user.has_usable_password():
            raise serializers.ValidationError(
                {"new_password": "Password has already been set."})

        return attrs


class ResetPasswordSerializer(serializers.Serializer):
    """
    Serializer for resetting a user's password.
    """
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True)
    retype_new_password = serializers.CharField(write_only=True)

    def validate_old_password(self, value):
        """
        Validate that the old password is correct.
        """
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError(
                _("Old password is not correct."))
        return value

    def validate_new_password(self, value):
        """
        Validate the new password using Django's built-in validators.
        """
        try:
            validate_password(value)
        except serializers.ValidationError as e:
            raise serializers.ValidationError({'new_password': e.messages})
        return value

    def validate(self, attrs):
        """
        Ensure the new password and confirmation match.
        """
        new_password = attrs.get('new_password')
        retype_new_password = attrs.get('retype_new_password')

        if new_password != retype_new_password:
            raise serializers.ValidationError(
                _("The two password fields didn't match."))

        # Validate the new password with Django's validators
        self.validate_new_password(new_password)

        return attrs

    def save(self, **kwargs):
        """
        Set the new password for the user.
        """
        user = self.context['request'].user
        user.set_password(self.validated_data['new_password'])
        user.save()
        return user


class OTPForDevSerializer(serializers.Serializer):
    """
    Serializer for OTP generation during development.
    """
    nonce = serializers.CharField(
        max_length=16,
        min_length=16,
        error_messages={
            'max_length': _('Nonce must be exactly 16 characters long.'),
            'min_length': _('Nonce must be exactly 16 characters long.')
        }
    )
