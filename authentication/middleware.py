from django.shortcuts import redirect
from django.urls import reverse


class LoginRequiredMiddleware:
    """Middleware to require login for home page"""
    
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # List of paths that require authentication
        protected_paths = ['/home/', '/']
        
        # Allow access to login, register, and static files
        if request.path.startswith('/admin/') or \
           request.path.startswith('/static/') or \
           request.path.startswith('/media/') or \
           request.path.startswith('/api/') or \
           '/login' in request.path or \
           '/register' in request.path:
            return self.get_response(request)
        
        # Check if path is protected and user is not authenticated
        if any(request.path.startswith(path) for path in protected_paths):
            if not request.user.is_authenticated:
                return redirect('login')
        
        return self.get_response(request)


