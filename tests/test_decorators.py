import pytest
from django.http import HttpResponse, HttpRequest
from django.test import RequestFactory, override_settings, Client
from pytest_django.lazy_django import skip_if_no_django

from modern_csrf.decorators import csrf_protect


@pytest.fixture(autouse=True)
def override_middleware_for_decorator_tests(settings):
    """Override MIDDLEWARE to be empty for all decorator tests."""
    settings.MIDDLEWARE = []


def simple_view(request: HttpRequest):
    """A simple unprotected view."""
    return HttpResponse("OK")


@csrf_protect
def protected_view(request: HttpRequest):
    """A view protected with csrf_protect decorator."""
    return HttpResponse("OK")


@pytest.fixture
def rf():
    """RequestFactory fixture."""
    return RequestFactory()


@pytest.fixture()
def client() -> Client:
    """A Django test client instance."""
    skip_if_no_django()

    from django.test import Client

    return Client(enforce_csrf_checks=True)


class TestSafeMethods:
    """Test that safe HTTP methods bypass CSRF protection."""

    @pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS", "TRACE"])
    def test_safe_methods_allowed(self, rf, method):
        """Safe methods should not require CSRF protection."""
        request = getattr(rf, method.lower())("/")
        response = protected_view(request)

        assert response.status_code == 200
        assert response.content == b"OK"
        assert hasattr(request, "csrf_processing_done")
        assert request.csrf_processing_done is True


class TestUnsafeMethods:
    """Test that unsafe HTTP methods require CSRF protection."""

    @pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH"])
    def test_unsafe_methods_without_headers_accepted(self, rf, method):
        """Unsafe methods without Origin or Sec-Fetch-Site headers should be accepted."""
        request = getattr(rf, method.lower())("/")
        response = protected_view(request)

        assert response.status_code == 200
        assert request.csrf_processing_done is True

    @pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH"])
    def test_unsafe_methods_with_bad_origin_rejected(self, rf, method):
        """Unsafe methods with bad origin should be rejected."""
        request = getattr(rf, method.lower())("/", HTTP_ORIGIN="https://evil.com")
        request.META["HTTP_HOST"] = "example.com"

        response = protected_view(request)

        assert response.status_code == 403


class TestOriginVerification:
    """Test Origin header verification with decorator."""

    def test_matching_origin_allowed(self, rf):
        """Request with matching origin should be allowed."""
        request = rf.post(
            "/", HTTP_ORIGIN="http://example.com", HTTP_HOST="example.com"
        )
        response = protected_view(request)

        assert response.status_code == 200
        assert request.csrf_processing_done is True

    def test_https_matching_origin_allowed(self, rf):
        """HTTPS request with matching origin should be allowed."""
        request = rf.post(
            "/", HTTP_ORIGIN="https://example.com", HTTP_HOST="example.com", secure=True
        )
        response = protected_view(request)

        assert response.status_code == 200
        assert request.csrf_processing_done is True

    def test_mismatched_origin_rejected(self, rf):
        """Request with mismatched origin should be rejected."""
        request = rf.post("/", HTTP_ORIGIN="https://evil.com", HTTP_HOST="example.com")
        response = protected_view(request)

        assert response.status_code == 403

    @override_settings(CSRF_TRUSTED_ORIGINS=["https://trusted.com"])
    def test_exact_trusted_origin_allowed(self, rf):
        """Request from exact trusted origin should be allowed."""

        # Create a fresh decorated view to pick up the settings override
        @csrf_protect
        def view_with_trusted_origins(request):
            return HttpResponse("OK")

        request = rf.post(
            "/", HTTP_ORIGIN="https://trusted.com", HTTP_HOST="example.com"
        )
        response = view_with_trusted_origins(request)

        assert response.status_code == 200
        assert request.csrf_processing_done is True

    @override_settings(CSRF_TRUSTED_ORIGINS=["https://*.example.com"])
    def test_subdomain_wildcard_allowed(self, rf):
        """Request from subdomain matching wildcard should be allowed."""

        # Create a fresh decorated view to pick up the settings override
        @csrf_protect
        def view_with_wildcard_origins(request):
            return HttpResponse("OK")

        request = rf.post(
            "/", HTTP_ORIGIN="https://api.example.com", HTTP_HOST="example.com"
        )
        response = view_with_wildcard_origins(request)

        assert response.status_code == 200
        assert request.csrf_processing_done is True

    @override_settings(CSRF_TRUSTED_ORIGINS=["https://*.example.com"])
    def test_subdomain_wildcard_nested_subdomain(self, rf):
        """Request from nested subdomain should be allowed."""

        # Create a fresh decorated view to pick up the settings override
        @csrf_protect
        def view_with_wildcard_origins(request):
            return HttpResponse("OK")

        request = rf.post(
            "/", HTTP_ORIGIN="https://v1.api.example.com", HTTP_HOST="example.com"
        )
        response = view_with_wildcard_origins(request)

        assert response.status_code == 200
        assert request.csrf_processing_done is True

    @override_settings(CSRF_TRUSTED_ORIGINS=["https://*.example.com"])
    def test_wildcard_wrong_scheme_rejected(self, rf):
        """Wildcard should respect scheme - http vs https."""

        # Create a fresh decorated view to pick up the settings override
        @csrf_protect
        def view_with_wildcard_origins(request):
            return HttpResponse("OK")

        request = rf.post(
            "/", HTTP_ORIGIN="http://api.example.com", HTTP_HOST="example.com"
        )
        response = view_with_wildcard_origins(request)

        assert response.status_code == 403

    def test_invalid_origin_rejected(self, rf):
        """Request with invalid/malformed origin should be rejected."""
        request = rf.post("/", HTTP_ORIGIN="not a valid url", HTTP_HOST="example.com")
        response = protected_view(request)

        assert response.status_code == 403


class TestSecFetchSite:
    """Test Sec-Fetch-Site header verification with decorator."""

    def test_same_origin_allowed(self, rf):
        """Request with Sec-Fetch-Site: same-origin should be allowed."""
        request = rf.post("/", HTTP_SEC_FETCH_SITE="same-origin")
        response = protected_view(request)

        assert response.status_code == 200
        assert request.csrf_processing_done is True

    def test_none_allowed(self, rf):
        """Request with Sec-Fetch-Site: none (user-initiated) should be allowed."""
        request = rf.post("/", HTTP_SEC_FETCH_SITE="none")
        response = protected_view(request)

        assert response.status_code == 200
        assert request.csrf_processing_done is True

    @pytest.mark.parametrize("fetch_site", ["cross-site", "same-site"])
    def test_cross_site_rejected(self, rf, fetch_site):
        """Request with Sec-Fetch-Site: cross-site should be rejected."""
        request = rf.post("/", HTTP_SEC_FETCH_SITE=fetch_site)
        response = protected_view(request)

        assert response.status_code == 403


class TestProcessingDoneFlag:
    """Test that already-processed requests are skipped."""

    def test_already_processed_request_skipped(self, rf):
        """Request with csrf_processing_done should be skipped even with bad origin."""
        request = rf.post("/", HTTP_ORIGIN="https://evil.com", HTTP_HOST="example.com")
        request.csrf_processing_done = True

        response = protected_view(request)

        # Should pass because csrf_processing_done is True
        assert response.status_code == 200


class TestDontEnforceCsrfChecks:
    """Test the _dont_enforce_csrf_checks flag for test suites."""

    def test_dont_enforce_flag_bypasses_check(self, rf):
        """Request with _dont_enforce_csrf_checks should bypass CSRF."""
        request = rf.post("/", HTTP_ORIGIN="https://evil.com", HTTP_HOST="example.com")
        request._dont_enforce_csrf_checks = True

        response = protected_view(request)

        assert response.status_code == 200
        assert request.csrf_processing_done is True


class TestDecoratorVsUnprotectedView:
    """Test that decorator actually provides protection vs unprotected views."""

    def test_unprotected_view_allows_bad_origin(self, rf):
        """Unprotected view should allow requests with bad origin."""
        request = rf.post("/", HTTP_ORIGIN="https://evil.com", HTTP_HOST="example.com")
        response = simple_view(request)

        # No CSRF protection, so it passes
        assert response.status_code == 200
        assert not hasattr(request, "csrf_processing_done")

    def test_protected_view_rejects_bad_origin(self, rf):
        """Protected view should reject requests with bad origin."""
        request = rf.post("/", HTTP_ORIGIN="https://evil.com", HTTP_HOST="example.com")
        response = protected_view(request)

        # CSRF protection active, so it's rejected
        assert response.status_code == 403
