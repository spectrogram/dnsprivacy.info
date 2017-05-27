from django.shortcuts import render, redirect, render_to_response
from django.http import HttpResponse, HttpResponseServerError
from ipware.ip import get_ip
from oracle.models import Resolver, Resolver_alt_name
from respoll.models import SurveyResponse
from django.core.exceptions import ObjectDoesNotExist
from django_user_agents.utils import get_user_agent

from greplog import scanlog, whois, scanlogqname
from automaton import createRes, checkPublic, nxdomainTest, dnssecTest1, dnssecTest2, censorshipTest1, censorshipTest2, censorshipTest3, dnsTLStest

def oracle(request):
   ip = get_ip(request)
   port = request.META['REMOTE_PORT']

   if ip is not None:
      iphyphenated = ip.replace(".", "-")
      iphyphenated = iphyphenated + "-" + str(port)
      redirecturl = "http://" + iphyphenated + ".dnsprivacy.info"
      redirecturl2 = "http://" + iphyphenated + ".minimisation.dnsprivacy.info"
      clientresolver = scanlog(ip)
      whois_name = whois(clientresolver)


      if whois_name is None:
         return render(request, "templates/oracle_error.html", status=503)

      if 'GOOGLE' in whois_name:
         resObject = createRes('8.8.8.8')
      elif 'OPENDNS' in whois_name:
         resObject = createRes('208.67.222.222')
      else:
         resObject = createRes(clientresolver)

      qnamemin = scanlogqname(resObject.nameservers[0])

      # most auto tests can only be done on public servers
      if checkPublic(resObject):
         isPublic = checkPublic(resObject)
         nxdomain = nxdomainTest(resObject)
         dnssec1 = dnssecTest1(resObject)
         dnssec2 = dnssecTest2(resObject)
         censorship1 = censorshipTest1(resObject)
         censorship2 = censorshipTest2(resObject)
         censorship3 = censorshipTest3(resObject)
         censorship3 = censorshipTest3(resObject)
         dnsovertls = dnsTLStest(resObject)

         try:
            resolver_alt = Resolver_alt_name.objects.get(name=whois_name)
         except ObjectDoesNotExist:
            print "Not found! Please look at IP " + clientresolver + " " + whois_name
            return render(request, "templates/oracle_autotest.html", 
            {'ip': ip, 
            'redirecturl': redirecturl, 
            'redirecturl2': redirecturl2,
            'clientresolver': clientresolver, 
            'whois_name': whois_name, 
            'isPublic': isPublic, 
            'dnssec1': dnssec1, 
            'dnssec2': dnssec2,
            'censorship1': censorship1,
            'censorship2': censorship2,
            'censorship3': censorship3,
            'nxdomain' : nxdomain,
            'qnamemin': qnamemin,
            'dnsovertls': dnsovertls})

         resolver = Resolver.objects.get(pk=resolver_alt.resolver_name)
         resolver_fields = ["resolver." + field.name for field in Resolver._meta.get_fields()][5:]
         request.session['resolver_ip'] = clientresolver
         return render(request, "templates/oracle_autotest.html", 
         {'ip': ip, 
         'redirecturl': redirecturl, 
         'redirecturl2': redirecturl2,
         'clientresolver': clientresolver, 
         'resolver': resolver,
         'resolver_fields': resolver_fields,
         'isPublic': isPublic,
         'dnssec1': dnssec1, 
         'dnssec2': dnssec2,
         'censorship1': censorship1,
         'censorship2': censorship2,
         'censorship3': censorship3,
         'nxdomain' : nxdomain,
         'qnamemin': qnamemin,
         'dnsovertls': dnsovertls})

      # following section is for non-public servers needing a survey

      # first find out how many responses there are
      # if less than 1 response, fallback to available information
      responses_count = SurveyResponse.objects.filter(name=whois_name).count()
      if responses_count < 1:
         try:
            resolver_alt = Resolver_alt_name.objects.get(name=whois_name)
         except ObjectDoesNotExist:
            print "Not found! Please look at IP " + clientresolver + " " + whois_name
            request.session['resolver_ip'] = clientresolver
            return render(request, "templates/oracle.html", 
            {'ip': ip, 
             'redirecturl': redirecturl, 
             'redirecturl2': redirecturl2,
             'clientresolver': clientresolver, 
             'whois_name': whois_name,
             'qnamemin': qnamemin,
             'responses_count': responses_count,})

         resolver = Resolver.objects.get(pk=resolver_alt.resolver_name)
         resolver_fields = ["resolver." + field.name for field in Resolver._meta.get_fields()][5:]
         return render(request, "templates/oracle.html", 
            {'ip': ip, 
            'redirecturl': redirecturl, 
            'redirecturl2': redirecturl2,
            'clientresolver': clientresolver, 
            'resolver': resolver,
            'resolver_fields': resolver_fields,
            'qnamemin': qnamemin,
            'responses_count': responses_count,})
      else:
         # here is some stupid logic to aggregate and average out all the fields

         dnssec_true_count = SurveyResponse.objects.filter(name=whois_name).filter(dnssec=True).count()
         dnssec_false_count = SurveyResponse.objects.filter(name=whois_name).filter(dnssec=False).count()
         ads_true_count = SurveyResponse.objects.filter(name=whois_name).filter(ads=True).count()
         ads_false_count = SurveyResponse.objects.filter(name=whois_name).filter(ads=False).count()
         cen1_true_count = SurveyResponse.objects.filter(name=whois_name).filter(censorship1=True).count()
         cen1_false_count = SurveyResponse.objects.filter(name=whois_name).filter(censorship1=False).count()
         cen2_true_count = SurveyResponse.objects.filter(name=whois_name).filter(censorship2=True).count()
         cen2_false_count = SurveyResponse.objects.filter(name=whois_name).filter(censorship2=False).count()
         cen3_true_count = SurveyResponse.objects.filter(name=whois_name).filter(censorship3=True).count()
         cen3_false_count = SurveyResponse.objects.filter(name=whois_name).filter(censorship3=False).count()

         if dnssec_true_count > dnssec_false_count:
            dnssec_supported = False
         else:
            dnssec_supported = True

         if ads_true_count > ads_false_count:
            nxdomain = True
         else:
            nxdomain = False

         if cen1_true_count > cen1_false_count:
            censor1 = True
         else:
            censor1 = False

         if cen2_true_count > cen2_false_count:
            censor2 = True
         else:
            censor2 = False

         if cen3_true_count > cen3_false_count:
            censor3 = True
         else:
            censor3 = False

         try:
            resolver_alt = Resolver_alt_name.objects.get(name=whois_name)
         except ObjectDoesNotExist:
            print "Not found! Please look at IP " + clientresolver + " " + whois_name
            request.session['resolver_ip'] = clientresolver
            return render(request, "templates/oracle_surveyed.html", 
            {'ip': ip, 
             'redirecturl': redirecturl, 
             'redirecturl2': redirecturl2,
             'clientresolver': clientresolver, 
             'whois_name': whois_name,
             'qnamemin': qnamemin,
             'responses_count': responses_count,
             'dnssec_supported': dnssec_supported,
             'nxdomain': nxdomain,
             'censor1': censor1,
             'censor2': censor2,
             'censor3': censor3,})

         resolver = Resolver.objects.get(pk=resolver_alt.resolver_name)
         resolver_fields = ["resolver." + field.name for field in Resolver._meta.get_fields()][5:]
         return render(request, "templates/oracle_surveyed.html", 
            {'ip': ip, 
            'redirecturl': redirecturl, 
            'redirecturl2': redirecturl2,
            'clientresolver': clientresolver, 
            'resolver': resolver,
            'resolver_fields': resolver_fields,
            'qnamemin': qnamemin,
            'responses_count': responses_count,
            'dnssec_supported': dnssec_supported,
            'nxdomain': nxdomain,
            'censor1': censor1,
            'censor2': censor2,
            'censor3': censor3,})

