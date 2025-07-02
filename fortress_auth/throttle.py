# backend/fortress_backend/fortress_auth/throttle.py
from datetime import timedelta
from django.utils import timezone
from .models import LoginAttempt

MAX_ATTEMPTS = 5
BLOCK_DURATION_MINUTES = 15

def is_blocked(ip_address):
    """
    Returns True if the IP address has exceeded the allowed number of failed login attempts
    in the last BLOCK_DURATION_MINUTES minutes.
    """
    time_threshold = timezone.now() - timedelta(minutes=BLOCK_DURATION_MINUTES)
    recent_failed_attempts = LoginAttempt.objects.filter(
        ip_address=ip_address,
        was_successful=False,
        timestamp__gte=time_threshold
    ).count()
    return recent_failed_attempts >= MAX_ATTEMPTS