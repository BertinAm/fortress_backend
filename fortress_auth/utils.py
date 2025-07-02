# fortress_auth/utils.py
def get_client_ip(request):
    """
    Extracts the client IP address from the request headers.
    Prioritizes X-Forwarded-For for proxy setups.
    """
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        # X-Forwarded-For may contain multiple IPs, take the first one
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get("REMOTE_ADDR")
    return ip