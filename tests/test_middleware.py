import pytest
from django.http import HttpResponse, HttpRequest
from django.test import RequestFactory, override_settings, Client
from django.views.decorators.csrf import csrf_exempt
from pytest_django.lazy_django import skip_if_no_django

from modern_csrf.middleware import ModernCsrfViewMiddleware


def simple_view(request: HttpRequest) -> HttpResponse:
    """A simple view that returns OK."""
    return HttpResponse("OK")


def protected_view(request: HttpRequest) -> HttpResponse:
    """A view that should be protected by CSRF."""
    return HttpResponse("OK")


@csrf_exempt
def exempt_view(request: HttpRequest) -> HttpResponse:
    """A view that is exempt from CSRF protection."""
    return HttpResponse("OK")


@pytest.fixture
def middleware():
    """Create a ModernCsrfViewMiddleware instance."""
    return ModernCsrfViewMiddleware(simple_view)


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
    def test_safe_methods_allowed(self, middleware, rf, method):
        """Safe methods should not require CSRF protection."""
        request = getattr(rf, method.lower())("/")
        result = middleware.process_view(request, protected_view, [], {})

        assert result is None
        assert hasattr(request, "csrf_processing_done")
        assert request.csrf_processing_done is True


class TestUnsafeMethods:
    """Test that unsafe HTTP methods require CSRF protection."""

    @pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH"])
    def test_unsafe_methods_without_headers_accepted(self, middleware, rf, method):
        """Unsafe methods without Origin or Sec-Fetch-Site headers should be accepted."""
        request = getattr(rf, method.lower())("/")
        result = middleware.process_view(request, protected_view, [], {})

        assert result is None
        assert request.csrf_processing_done is True

    @pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH"])
    def test_unsafe_methods_with_bad_origin_rejected(self, middleware, rf, method):
        """Unsafe methods with bad origin should be rejected."""
        request = getattr(rf, method.lower())("/", HTTP_ORIGIN="https://evil.com")
        request.META["HTTP_HOST"] = "example.com"

        result = middleware.process_view(request, protected_view, [], {})

        assert isinstance(result, HttpResponse)
        assert result.status_code == 403


class TestOriginVerification:
    """Test Origin header verification."""

    def test_matching_origin_allowed(self, middleware, rf):
        """Request with matching origin should be allowed."""
        request = rf.post(
            "/", HTTP_ORIGIN="http://example.com", HTTP_HOST="example.com"
        )
        result = middleware.process_view(request, protected_view, [], {})

        assert result is None
        assert request.csrf_processing_done is True

    def test_https_matching_origin_allowed(self, middleware, rf):
        """HTTPS request with matching origin should be allowed."""
        request = rf.post(
            "/", HTTP_ORIGIN="https://example.com", HTTP_HOST="example.com", secure=True
        )
        result = middleware.process_view(request, protected_view, [], {})

        assert result is None
        assert request.csrf_processing_done is True

    def test_mismatched_origin_rejected(self, middleware, rf):
        """Request with mismatched origin should be rejected."""
        request = rf.post("/", HTTP_ORIGIN="https://evil.com", HTTP_HOST="example.com")
        result = middleware.process_view(request, protected_view, [], {})

        assert isinstance(result, HttpResponse)
        assert result.status_code == 403

    @override_settings(CSRF_TRUSTED_ORIGINS=["https://trusted.com"])
    def test_exact_trusted_origin_allowed(self, rf):
        """Request from exact trusted origin should be allowed."""
        middleware = ModernCsrfViewMiddleware(simple_view)
        request = rf.post(
            "/", HTTP_ORIGIN="https://trusted.com", HTTP_HOST="example.com"
        )
        result = middleware.process_view(request, protected_view, [], {})

        assert result is None
        assert request.csrf_processing_done is True

    @override_settings(CSRF_TRUSTED_ORIGINS=["https://*.example.com"])
    def test_subdomain_wildcard_allowed(self, rf):
        """Request from subdomain matching wildcard should be allowed."""
        middleware = ModernCsrfViewMiddleware(simple_view)
        request = rf.post(
            "/", HTTP_ORIGIN="https://api.example.com", HTTP_HOST="example.com"
        )
        result = middleware.process_view(request, protected_view, [], {})

        assert result is None
        assert request.csrf_processing_done is True

    @override_settings(CSRF_TRUSTED_ORIGINS=["https://*.example.com"])
    def test_subdomain_wildcard_nested_subdomain(self, rf):
        """Request from nested subdomain should be allowed."""
        middleware = ModernCsrfViewMiddleware(simple_view)
        request = rf.post(
            "/", HTTP_ORIGIN="https://v1.api.example.com", HTTP_HOST="example.com"
        )
        result = middleware.process_view(request, protected_view, [], {})

        assert result is None
        assert request.csrf_processing_done is True

    @override_settings(CSRF_TRUSTED_ORIGINS=["https://*.example.com"])
    def test_wildcard_wrong_scheme_rejected(self, rf):
        """Wildcard should respect scheme - http vs https."""
        middleware = ModernCsrfViewMiddleware(simple_view)
        request = rf.post(
            "/", HTTP_ORIGIN="http://api.example.com", HTTP_HOST="example.com"
        )
        result = middleware.process_view(request, protected_view, [], {})

        assert isinstance(result, HttpResponse)
        assert result.status_code == 403

    def test_invalid_origin_rejected(self, middleware, rf):
        """Request with invalid/malformed origin should be rejected."""
        request = rf.post("/", HTTP_ORIGIN="not a valid url", HTTP_HOST="example.com")
        result = middleware.process_view(request, protected_view, [], {})

        assert isinstance(result, HttpResponse)
        assert result.status_code == 403

    @override_settings(ALLOWED_HOSTS=["example.com"])
    def test_disallowed_host_origin_check(self, rf):
        """Request with disallowed host should still check other origins."""
        middleware = ModernCsrfViewMiddleware(simple_view)
        # Set HTTP_HOST to something not in ALLOWED_HOSTS to trigger DisallowedHost
        request = rf.post(
            "/", HTTP_ORIGIN="https://evil.com", HTTP_HOST="not-allowed.com"
        )
        result = middleware.process_view(request, protected_view, [], {})

        # Should still reject because origin doesn't match trusted origins
        assert isinstance(result, HttpResponse)
        assert result.status_code == 403

    @override_settings(
        ALLOWED_HOSTS=["example.com"], CSRF_TRUSTED_ORIGINS=["https://trusted.com"]
    )
    def test_disallowed_host_with_trusted_origin_accepted(self, rf):
        """Request with disallowed host but valid trusted origin should be accepted."""
        middleware = ModernCsrfViewMiddleware(simple_view)
        # Set HTTP_HOST to something not in ALLOWED_HOSTS to trigger DisallowedHost
        # But provide a valid trusted origin
        request = rf.post(
            "/", HTTP_ORIGIN="https://trusted.com", HTTP_HOST="not-allowed.com"
        )
        result = middleware.process_view(request, protected_view, [], {})

        # Should be accepted because origin matches trusted origins
        assert result is None
        assert request.csrf_processing_done is True

    def test_origin_with_invalid_url_structure_rejected(self, middleware, rf):
        """Request with origin that causes ValueError in urlsplit should be rejected."""
        # Create a string that will cause urlsplit to raise ValueError
        # Malformed IPv6 address in URL triggers ValueError
        request = rf.post("/", HTTP_ORIGIN="http://[ff60", HTTP_HOST="example.com")
        result = middleware.process_view(request, protected_view, [], {})

        assert isinstance(result, HttpResponse)
        assert result.status_code == 403


class TestSecFetchSite:
    """Test Sec-Fetch-Site header verification."""

    def test_same_origin_allowed(self, middleware, rf):
        """Request with Sec-Fetch-Site: same-origin should be allowed."""
        request = rf.post("/", HTTP_SEC_FETCH_SITE="same-origin")
        result = middleware.process_view(request, protected_view, [], {})

        assert result is None
        assert request.csrf_processing_done is True

    def test_none_allowed(self, middleware, rf):
        """Request with Sec-Fetch-Site: none (user-initiated) should be allowed."""
        request = rf.post("/", HTTP_SEC_FETCH_SITE="none")
        result = middleware.process_view(request, protected_view, [], {})

        assert result is None
        assert request.csrf_processing_done is True

    @pytest.mark.parametrize("fetch_site", ["cross-site", "same-site"])
    def test_cross_or_same_site_without_origin_rejected(
        self, middleware, rf, fetch_site
    ):
        """Request with Sec-Fetch-Site: cross-site/same-site without Origin header should be rejected."""
        request = rf.post("/", HTTP_SEC_FETCH_SITE=fetch_site)
        result = middleware.process_view(request, protected_view, [], {})

        assert isinstance(result, HttpResponse)
        assert result.status_code == 403

    @pytest.mark.parametrize("fetch_site", ["cross-site", "same-site"])
    @override_settings(CSRF_TRUSTED_ORIGINS=["https://trusted.com"])
    def test_cross_or_same_site_with_verified_origin_allowed(self, rf, fetch_site):
        """Request with Sec-Fetch-Site: cross-site/same-site with verified Origin should be allowed."""
        middleware = ModernCsrfViewMiddleware(protected_view)
        request = rf.post(
            "/",
            HTTP_SEC_FETCH_SITE=fetch_site,
            HTTP_ORIGIN="https://trusted.com",
            HTTP_HOST="example.com",
        )
        result = middleware.process_view(request, protected_view, [], {})

        assert result is None
        assert request.csrf_processing_done is True

    @pytest.mark.parametrize("fetch_site", ["cross-site", "same-site"])
    def test_cross_or_same_site_with_unverified_origin_rejected(
        self, middleware, rf, fetch_site
    ):
        """Request with Sec-Fetch-Site: cross-site/same-site with unverified Origin should be rejected."""
        request = rf.post(
            "/",
            HTTP_SEC_FETCH_SITE=fetch_site,
            HTTP_ORIGIN="https://evil.com",
            HTTP_HOST="example.com",
        )
        result = middleware.process_view(request, protected_view, [], {})

        assert isinstance(result, HttpResponse)
        assert result.status_code == 403

    @override_settings(
        ALLOWED_HOSTS=[".example.com"], CSRF_TRUSTED_ORIGINS=["https://*.example.com"]
    )
    def test_same_site_with_trusted_subdomain_allowed(self, rf):
        """Request with Sec-Fetch-Site: same-site from trusted subdomain should be allowed."""
        middleware = ModernCsrfViewMiddleware(protected_view)
        request = rf.post(
            "/",
            HTTP_SEC_FETCH_SITE="same-site",
            HTTP_ORIGIN="https://subdomain1.example.com",
            HTTP_HOST="subdomain1.example.com",
        )
        result = middleware.process_view(request, protected_view, [], {})

        assert result is None
        assert request.csrf_processing_done is True


class TestCsrfExempt:
    """Test csrf_exempt decorator support."""

    def test_exempt_view_bypasses_check(self, middleware, rf):
        """Views decorated with csrf_exempt should bypass CSRF checks."""
        request = rf.post("/", HTTP_ORIGIN="https://evil.com", HTTP_HOST="example.com")
        result = middleware.process_view(request, exempt_view, [], {})

        assert result is None

    def test_exempt_view_no_processing_done_flag(self, middleware, rf):
        """Exempt views should not set csrf_processing_done."""
        request = rf.post("/")
        result = middleware.process_view(request, exempt_view, [], {})

        assert result is None
        assert not hasattr(request, "csrf_processing_done")


class TestProcessingDoneFlag:
    """Test that already-processed requests are skipped."""

    def test_already_processed_request_skipped(self, middleware, rf):
        """Request with csrf_processing_done should be skipped."""
        request = rf.post("/", HTTP_ORIGIN="https://evil.com")
        request.csrf_processing_done = True

        result = middleware.process_view(request, protected_view, [], {})

        assert result is None


class TestDontEnforceCsrfChecks:
    """Test the _dont_enforce_csrf_checks flag for test suites."""

    def test_dont_enforce_flag_bypasses_check(self, middleware, rf):
        """Request with _dont_enforce_csrf_checks should bypass CSRF."""
        request = rf.post("/", HTTP_ORIGIN="https://evil.com", HTTP_HOST="example.com")
        request._dont_enforce_csrf_checks = True

        result = middleware.process_view(request, protected_view, [], {})

        assert result is None
        assert request.csrf_processing_done is True


class TestAllowedOriginsCaching:
    """Test that allowed origins are cached properly."""

    @override_settings(
        CSRF_TRUSTED_ORIGINS=[
            "https://exact.com",
            "https://*.wildcard.com",
            "http://another-exact.com",
        ]
    )
    def test_allowed_origins_exact_cached(self):
        """Exact origins should be cached."""
        middleware = ModernCsrfViewMiddleware(simple_view)

        assert middleware.allowed_origins_exact == {
            "https://exact.com",
            "http://another-exact.com",
        }

    @override_settings(
        CSRF_TRUSTED_ORIGINS=[
            "https://exact.com",
            "https://*.wildcard.com",
            "http://*.another.com",
        ]
    )
    def test_allowed_origin_subdomains_cached(self):
        """Wildcard origins should be cached by scheme."""
        middleware = ModernCsrfViewMiddleware(simple_view)

        subdomains = middleware.allowed_origin_subdomains
        assert "https" in subdomains
        assert "http" in subdomains
        assert ".wildcard.com" in subdomains["https"]
        assert ".another.com" in subdomains["http"]


class TestMiddlewareIntegration:
    """Integration tests using Django test client to verify middleware works in full Django stack."""

    def test_safe_request_allowed(self, client):
        """Safe GET request should work through full Django stack."""
        response = client.get("/protected/")
        assert response.status_code == 200
        assert response.content == b"OK"

    def test_post_with_sec_fetch_site_same_origin_accepts(self, client):
        """POST with Sec-Fetch-Site: same-origin should be accepted."""
        response = client.post("/protected/", headers={"sec-fetch-site": "same-origin"})
        assert response.status_code == 200

    def test_post_with_bad_origin_rejects(self, client):
        """POST request with bad Origin header should reject."""
        response = client.post("/protected/", headers={"origin": "https://evil.com"})
        assert response.status_code == 403

    def test_csrf_exempt_view_bypasses_protection(self, client):
        """CSRF exempt views should work even with bad origin."""
        response = client.post("/exempt/", headers={"origin": "https://evil.com"})
        assert response.status_code == 200
