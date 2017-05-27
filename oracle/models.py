from __future__ import unicode_literals

from django.db import models
from django_countries.fields import CountryField

class Resolver(models.Model):
   operator = models.CharField(max_length=50)
   resolver_name = models.CharField(max_length=100, primary_key=True)
   country = CountryField()
   ips = models.TextField()
   dnssec = models.BooleanField()
   dnssec_details = models.TextField(blank=True)
   censorship = models.BooleanField()
   censorship_details = models.TextField(blank=True)
   qnamemin = models.BooleanField()
   qnamemin_details = models.TextField(blank=True)
   tls = models.BooleanField()
   tls_details = models.TextField(blank=True)
   tos = models.BooleanField()
   tos_details = models.TextField(blank=True)
   ads = models.BooleanField()
   ads_details = models.TextField(blank=True)

   def __unicode__(self):
      return self.resolver_name

class Resolver_alt_name(models.Model):
   name = models.CharField(max_length=50)
   resolver_name = models.ForeignKey(Resolver, on_delete=models.CASCADE)

   def __unicode__(self):
      return self.name