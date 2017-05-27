from django.shortcuts import render
from django.http import HttpResponse, HttpResponseRedirect
from ipware.ip import get_ip
from .models import SurveyResponse
from .forms import ResolverPoll
from django_user_agents.utils import get_user_agent

from oracle.greplog import scanlog, whois

def index(request):   
   user_agent = get_user_agent(request)
   mobile = user_agent.is_mobile

   if request.method == "POST":
      response = SurveyResponse()
      response.name = request.POST.get('name');
      response.dnssec = request.POST.get('dnssec');
      response.ads = request.POST.get('ads');
      response.censorship1 = not request.POST.get('censorship1');
      response.censorship2 = not request.POST.get('censorship2');
      response.censorship3 = not request.POST.get('censorship3');

      response.save()
      return render(request, "templates/poll_success.html")
   else:
      ip = get_ip(request)

      if ip is not None:
         clientresolver = scanlog(ip)
         whois_name = whois(clientresolver)

      if whois_name is None:
         return render(request, "templates/oracle_error.html", status=503)

      form = ResolverPoll(initial={'name': whois_name})

      return render(request, "templates/poll.html", 
               {'form': form,
               'clientresolver': clientresolver, 
               'whois_name': whois_name,
               'mobile': mobile,})