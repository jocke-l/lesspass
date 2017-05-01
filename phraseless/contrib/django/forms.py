from base64 import urlsafe_b64decode

from django import forms

from phraseless.certificates import deserialize_certificate_chain


class CertificateAuth(forms.Form):
    certificate_chain = forms.CharField()
    challenge_signature = forms.CharField()

    def clean_certificate_chain(self):
        return deserialize_certificate_chain(
            self.cleaned_data['certificate_chain'].encode()
        )

    def clean_challenge_signature(self):
        return urlsafe_b64decode(
            self.cleaned_data['challenge_signature'].encode()
        )
