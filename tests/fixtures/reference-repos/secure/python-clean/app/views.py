from django.utils.html import escape
from django.http import HttpResponse


def show_bio(request, user_bio):
    return HttpResponse(escape(user_bio))
