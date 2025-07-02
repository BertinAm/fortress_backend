from django.utils.deprecation import MiddlewareMixin
from .utils import sanitize_input

class XSSSanitizerMiddleware(MiddlewareMixin):
    def process_request(self, request):
        if request.method == "POST":
            for key, value in request.POST.items():
                request.POST._mutable = True
                request.POST[key] = sanitize_input(value)
                request.POST._mutable = False