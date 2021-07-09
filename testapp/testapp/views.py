from django.shortcuts import render


def test(request):
    response = render(request, 'test.html')
    response['Content-Security-Policy'] = "require-trusted-types-for 'script';"
    return response
