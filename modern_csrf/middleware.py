import logging
from collections import defaultdict
from urllib.parse import urlsplit

from django.conf import settings
from django.core.exceptions import DisallowedHost
from django.http import HttpRequest, HttpResponse
from django.urls import get_callable
from django.utils.deprecation import MiddlewareMixin
from django.utils.functional import cached_property
from django.utils.http import is_same_domain
from django.utils.log import log_response

logger = logging.getLogger("modern_csrf")

REASON_BAD_ORIGIN = "Origin checking failed - %s does not match any trusted origins."
REASON_BAD_SEC_FETCH_SITE = (
    "Cross-origin request detected via the Sec-Fetch-Site header."
)


def _get_failure_view():
    """Return the view to be used for CSRF rejections."""
    return get_callable(settings.CSRF_FAILURE_VIEW)


class ModernCsrfViewMiddleware(MiddlewareMixin):
    @cached_property
    def allowed_origins_exact(self):
        return {origin for origin in settings.CSRF_TRUSTED_ORIGINS if "*" not in origin}

    @cached_property
    def allowed_origin_subdomains(self):
        """
        A mapping of allowed schemes to list of allowed netlocs, where all
        subdomains of the netloc are allowed.
        """
        allowed_origin_subdomains = defaultdict(list)
        for parsed in (
            urlsplit(origin)
            for origin in settings.CSRF_TRUSTED_ORIGINS
            if "*" in origin
        ):
            allowed_origin_subdomains[parsed.scheme].append(parsed.netloc.lstrip("*"))
        return allowed_origin_subdomains

    def _accept(self, request: HttpRequest) -> None:
        # From Django CsrfViewMiddleware
        # Avoid checking the request twice by adding a custom attribute to
        # request. This will be relevant when both decorator and middleware
        # are used.
        request.csrf_processing_done = True
        return None

    def _reject(self, request: HttpRequest, reason: str) -> HttpResponse:
        # From Django CsrfViewMiddleware
        response = _get_failure_view()(request, reason=reason)
        log_response(
            "Forbidden (%s): %s",
            reason,
            request.path,
            response=response,
            request=request,
            logger=logger,
        )
        return response

    def _origin_verified(self, request: HttpRequest):
        request_origin = request.META["HTTP_ORIGIN"]
        try:
            good_host = request.get_host()
        except DisallowedHost:
            pass
        else:
            good_origin = "%s://%s" % (
                "https" if request.is_secure() else "http",
                good_host,
            )
            if request_origin == good_origin:
                return True
        if request_origin in self.allowed_origins_exact:
            return True
        try:
            parsed_origin = urlsplit(request_origin)
        except ValueError:
            return False
        return any(
            is_same_domain(parsed_origin.netloc, host)
            for host in self.allowed_origin_subdomains.get(parsed_origin.scheme, ())
        )

    def has_verified_origin(self, request: HttpRequest) -> bool:
        """Check if Origin header is present and verified."""
        return "HTTP_ORIGIN" in request.META and self._origin_verified(request)

    def process_view(self, request, callback, callback_args, callback_kwargs):
        if getattr(request, "csrf_processing_done", False):
            return None

        # Wait until request.META["CSRF_COOKIE"] has been manipulated before
        # bailing out, so that get_token still works
        if getattr(callback, "csrf_exempt", False):
            return None

        # Assume that anything not defined as 'safe' by RFC 9110 needs
        # protection
        if request.method in ("GET", "HEAD", "OPTIONS", "TRACE"):
            return self._accept(request)

        if getattr(request, "_dont_enforce_csrf_checks", False):
            # Mechanism to turn off CSRF checks for test suite. It comes after
            # the creation of CSRF cookies, so that everything else continues
            # to work exactly the same (e.g. cookies are sent, etc.), but
            # before any branches that call the _reject method.
            return self._accept(request)

        # If the Sec-Fetch-Site header is set, we can use it along with Origin
        # to prevent CSRF attacks.
        if "HTTP_SEC_FETCH_SITE" in request.META:
            if request.META["HTTP_SEC_FETCH_SITE"] in ("same-origin", "none"):
                # If the request is from the same origin or user-initiated,
                # we can proceed without checking the Origin header.
                return self._accept(request)
            # If the Sec-Fetch-Site is cross-site or same-site, we verify
            # the Origin header.
            if self.has_verified_origin(request):
                return self._accept(request)
            # If there's no Origin header or the origin doesn't match, reject
            # the request.
            return self._reject(request, REASON_BAD_SEC_FETCH_SITE)

        # Reject the request if the Origin header is present but doesn't match
        # an allowed value.
        if "HTTP_ORIGIN" in request.META:
            if not self._origin_verified(request):
                return self._reject(
                    request, REASON_BAD_ORIGIN % request.META["HTTP_ORIGIN"]
                )

        return self._accept(request)
