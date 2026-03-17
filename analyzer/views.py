import json
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .scanner import full_scan


def index(request):
    return render(request, 'analyzer/index.html')


@csrf_exempt
def scan(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)

    try:
        body = json.loads(request.body)
        url = body.get("url", "").strip()
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    if not url:
        return JsonResponse({"error": "URL is required"}, status=400)

    # Add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        results = full_scan(url)
        return JsonResponse(results)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)
