from django.utils.safestring import mark_safe
from django.utils.html import escape
from django.http import HttpResponse


def show_bio_unsafe(request, user_bio):
    return HttpResponse(mark_safe(user_bio))


def show_bio_safe(request, user_bio):
    return HttpResponse(escape(user_bio))
