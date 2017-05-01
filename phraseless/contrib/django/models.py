from django.conf import settings
from django.db import models
from django.db.models import query

from phraseless.certificates import Certificate as Certificate_
from phraseless.certificates import decode_certificate


class CertificateQuerySet(query.QuerySet):
    def to_tuples(self):
        for certificate in self:
            yield certificate.to_tuple()


class Certificate(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL,
                             related_name='certificates')
    public_key: str = models.TextField()
    signature: str = models.TextField()

    objects = CertificateQuerySet.as_manager()

    def to_tuple(self) -> Certificate_:
        return decode_certificate(self.user.username, self.public_key,
                                  self.signature)

    class Meta:
        app_label = 'phraseless'
