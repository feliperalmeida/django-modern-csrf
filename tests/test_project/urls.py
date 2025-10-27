from django.urls import path
from .views import project_protected_view, project_exempt_view

urlpatterns = [
    path("protected/", project_protected_view, name="protected"),
    path("exempt/", project_exempt_view, name="exempt"),
]
