SECRET_KEY = "django-insecure-test-key"
DEBUG = True
ALLOWED_HOSTS = ["example.com"]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "modern_csrf",
]

MIDDLEWARE = [
    "modern_csrf.middleware.ModernCsrfViewMiddleware",
]

ROOT_URLCONF = "tests.test_project.urls"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

USE_TZ = True
