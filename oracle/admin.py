from django.contrib import admin
from .models import Resolver, Resolver_alt_name

# Register your models here.
admin.site.register(Resolver)
admin.site.register(Resolver_alt_name)