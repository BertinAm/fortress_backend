# fortress_auth/urls.py
from django.urls import path
from .views import LoginView, UserRegistrationView, PasswordResetView

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('reset-password/', PasswordResetView.as_view(), name='reset-password'),
]
