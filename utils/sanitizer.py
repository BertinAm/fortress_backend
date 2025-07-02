# utils/sanitizer.py

from urllib.parse import urlparse

def sanitize_url(url):
    """
    Ensure the URL is well-formed and starts with http or https.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ['http', 'https']:
        raise ValueError("Only http and https URLs are allowed.")
    return url.strip()
