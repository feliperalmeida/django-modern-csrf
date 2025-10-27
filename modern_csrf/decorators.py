from django.utils.decorators import decorator_from_middleware

from modern_csrf.middleware import ModernCsrfViewMiddleware

csrf_protect = decorator_from_middleware(ModernCsrfViewMiddleware)
csrf_protect.__name__ = "csrf_protect"
csrf_protect.__doc__ = """
This decorator adds the CSRF protection in exactly the same way as
ModernCsrfViewMiddleware, but it can be used on a per view basis. Using both, or
using the decorator multiple times, is harmless and efficient.
"""
