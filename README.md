# django-modern-csrf

[![PyPI version](https://badge.fury.io/py/django-modern-csrf.svg)](https://badge.fury.io/py/django-modern-csrf)
[![PyPI Supported Python Versions](https://img.shields.io/pypi/pyversions/django-modern-csrf.svg)](https://pypi.python.org/pypi/django-modern-csrf/)
[![tests](https://github.com/feliperalmeida/django-modern-csrf/actions/workflows/main.yml/badge.svg?branch=main)](https://github.com/feliperalmeida/django-modern-csrf/actions/workflows/main.yml)
[![codecov](https://codecov.io/github/feliperalmeida/django-modern-csrf/graph/badge.svg?token=F8O6BPUYPH)](https://codecov.io/github/feliperalmeida/django-modern-csrf)

Django modern CSRF protection using **Fetch metadata** request headers, without tokens, cookies or custom headers. No
more CSRF token errors, `csrf_token` in your templates or configuring frontend clients to deal with `X-CSRFToken`.

## Rationale

Django's default [CSRF protection](https://docs.djangoproject.com/en/5.2/ref/csrf/) relies on tokens and cookies. While
this works well and is secure, there are more
modern ways to protect against CSRF attacks, without requiring to submit CSRF tokens to the server via forms, cookies or
custom headers.
[Fetch metadata request headers](https://developer.mozilla.org/en-US/docs/Glossary/Fetch_metadata_request_header)
provide a way to protect against CSRF attacks without requiring token verifications. The `Sec-Fetch-Site` in particular,
tells the server whether the request is same origin, cross-origin, same site or user initiated. With that information,
the server can decide whether to allow the request or not.

To learn more about Fetch metadata request headers and how they can be used for web security, check out this
[article](https://web.dev/fetch-metadata/) by Google.

According to Can I Use, the `Sec-Fetch-Site` header is supported
by [97.63%](https://caniuse.com/mdn-http_headers_sec-fetch-site) and `Origin`
by [99.83%](https://caniuse.com/mdn-http_headers_origin) of all tracked browsers.

## Installation

This package is designed to require minimal changes to your existing Django project.

1. Install the package:

```bash
pip install django-modern-csrf
```

2. Add `modern_csrf` to your `INSTALLED_APPS`:

```python
# settings.py

INSTALLED_APPS = [
    ...
    "modern_csrf",
    ...
]
```

3. Replace the default CSRF middleware with the new one (in the same position):

```python
# settings.py

# Old
MIDDLEWARE = [
    ...
    "django.middleware.csrf.CsrfViewMiddleware",
    ...
]

# New
MIDDLEWARE = [
    ...
    "modern_csrf.middleware.ModernCsrfViewMiddleware",
    ...
]
```

4. That should be it for most projects. However, if you are using the `@csrf_protect` decorator, you will need to
   replace
   it with this package's `@csrf_protect`.

```python
# Old
from django.views.decorators.csrf import csrf_protect

# Replace with
from modern_csrf.decorators import csrf_protect
```

5. That's it! You can remove all references to `{% csrf_token %}` or `{{ csrf_token }}` from your templates. You can
   also
   remove any code in your JavaScript clients that sets the `X-CSRFToken` header, as there are no more token checks in
   place. Enjoy your tokenless CSRF protection!

## Implementation

The implementation for this package is based on the Go standard library's protection against CSRF attacks. The
implementation can be seen [here](https://cs.opensource.google/go/go/+/refs/tags/go1.25rc2:src/net/http/csrf.go;l=122),
along with the [research by the author](https://words.filippo.io/csrf/) who implemented it.

The `ModernCsrfViewMiddleware` is a drop-in replacement for the default `CsrfViewMiddleware` that uses the
`Sec-Fetch-Site` header to determine whether to allow the request or not. Below is a description of how it works:

1. Skip CSRF protection if the view is explicitly marked as CSRF-exempt.

2. Allow all GET, HEAD, OPTIONS, or TRACE requests.

   These are safe methods as defined by RFC 9110, and are assumed not to change state.

3. If the `Sec-Fetch-Site` header is present:
    - if its value is `same-origin` or `none`, allow the request;
    - otherwise, check if the `Origin` header is verified against trusted origins (Django's `CSRF_TRUSTED_ORIGINS`);
    - if the Origin is verified, allow the request;
    - otherwise, reject the request.

   This leverages modern browser security headers to detect cross-origin requests. The `Sec-Fetch-Site` header is
   automatically sent by modern browsers and provides reliable origin information.

4. If the `Origin` header is present but doesn't match any trusted origin, reject the request.

   This catches cross-origin requests from browsers that don't support `Sec-Fetch-Site` but do send `Origin` headers.

5. If neither the `Sec-Fetch-Site` nor the `Origin` headers triggered a rejection, allow the request.

   This is the default fallback for requests that don't present obvious cross-origin indicators. Those requests are most
   likely from command line tools or other non-browser clients.

Origin verification checks three conditions:

- (1) the Origin matches the current request's origin (scheme + host + port if present),
- (2) the Origin is in the `CSRF_TRUSTED_ORIGINS` allow-list as an exact match,
- (3) the Origin's domain is a subdomain of an allowed wildcard entry in `CSRF_TRUSTED_ORIGINS`.

This approach prioritizes the Sec-Fetch-Site header, which provides the most reliable protection for modern browsers,
while maintaining backward compatibility through
Origin header validation. The algorithm has no false negatives in browsers that support Sec-Fetch-Site (all major
browsers since 2020), and degrades gracefully for older browsers.

## Acknowledgements

Thanks to [Filippo Valsorda](https://github.com/FiloSottile) for the research and implementation of Go's
`CrossOriginProtection` which this package is based on.
