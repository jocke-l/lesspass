from django.contrib.auth import authenticate as authenticate_
from django.http import HttpResponse

from phraseless.contrib.django.forms import CertificateAuth


def authenticate(request):
    form = CertificateAuth(request.POST)
    if form.is_valid():
        user = authenticate_(
            request,
            certificate_chain=form.cleaned_data['certificate_chain'],
            signature=form.cleaned_data['challenge_signature']
        )
    else:
        user = None

    response = HttpResponse()
    if user:
        response['X-Authenticated'] = 'yes'
    else:
        response['X-Authenticated'] = 'no'

    return response

