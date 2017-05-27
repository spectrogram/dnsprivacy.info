from __future__ import unicode_literals

from django.db import models

class SurveyResponse(models.Model):
   name = models.CharField(max_length=50)
   dnssec = models.BooleanField()
   censorship1 = models.BooleanField()
   censorship2 = models.BooleanField()
   censorship3 = models.BooleanField()
   ads = models.BooleanField()

   def __unicode__(self):
      return self.name
