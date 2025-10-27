from django.http import HttpRequest, HttpResponse
from django.views.decorators.csrf import csrf_exempt


def project_protected_view(request: HttpRequest):
    return HttpResponse("OK")


@csrf_exempt
def project_exempt_view(request: HttpRequest):
    return HttpResponse("OK")
