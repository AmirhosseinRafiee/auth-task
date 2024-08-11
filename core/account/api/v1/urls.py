from django.conf import settings
from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.LoginAPIView.as_view(), name='login'),
    path('login/otp/', views.LoginOTPAPIView.as_view(), name='login-otp'),
    path('login-password/', views.LoginPasswordAPIView.as_view(), name='login-password'),
    path('user/', views.UserRetrieveUpdateAPIView.as_view(), name='user-info'),
    path('set-password/', views.SetPasswordAPIView.as_view(), name='set-password'),
    path('reset-password/', views.ResetPasswordAPIView.as_view(), name='reset-password'),
]

# Add development-specific endpoints if in DEBUG mode
if settings.DEBUG:
    urlpatterns += [
        path('otp-for-dev/', views.DevOTPAPIView.as_view(), name='otp-for-dev'),
    ]
