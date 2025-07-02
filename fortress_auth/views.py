from django.contrib.auth import authenticate
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import User
from rest_framework.permissions import AllowAny

from .serializers import LoginSerializer
from .utils import get_client_ip
from .models import LoginAttempt
from .throttle import is_blocked

# Create your views here.
class LoginView(APIView):
    permission_classes = [AllowAny]
    """Login endpoint with brute-force prevention and JWT token return."""

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        username = serializer.validated_data['username']
        password = serializer.validated_data['password']
        ip = get_client_ip(request)

        if is_blocked(ip):
            return Response(
                {"detail": "Too many failed attempts. Try again later."},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )

        user = authenticate(username=username, password=password)
        if user:
            LoginAttempt.objects.create(ip_address=ip, username=username, was_successful=True)
            refresh = RefreshToken.for_user(user)
            return Response({
                "detail": "Login successful",
                "access": str(refresh.access_token),
                "refresh": str(refresh)
            }, status=status.HTTP_200_OK)
        else:
            LoginAttempt.objects.create(ip_address=ip, username=username, was_successful=False)
            return Response({"detail": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

class UserRegistrationView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        if not username or not password:
            return Response({'detail': 'Username and password required.'}, status=status.HTTP_400_BAD_REQUEST)
        if User.objects.filter(username=username).exists():
            return Response({'detail': 'Username already exists.'}, status=status.HTTP_400_BAD_REQUEST)
        user = User.objects.create_user(username=username, password=password)
        return Response({'detail': 'User registered successfully.'}, status=status.HTTP_201_CREATED)

class PasswordResetView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        username = request.data.get('username')
        new_password = request.data.get('new_password')
        if not username or not new_password:
            return Response({'detail': 'Username and new password required.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(username=username)
            user.set_password(new_password)
            user.save()
            return Response({'detail': 'Password reset successful.'}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'detail': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)