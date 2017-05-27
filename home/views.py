from django.shortcuts import render
from ipware.ip import get_ip

def index(request):
   ip = get_ip(request)
   port = request.META['REMOTE_PORT']

   if ip is not None:
      iphyphenated = ip.replace(".", "-")
      iphyphenated = iphyphenated + "-" + str(port)
      redirecturl = "http://" + iphyphenated + ".dnsprivacy.info"
      redirecturl2 = "http://" + iphyphenated + ".minimisation.dnsprivacy.info"
   else:
      print("we don't have an IP address for user")

   return render(request, "templates/index.html", {'ip': ip, 'redirecturl': redirecturl, 'redirecturl2': redirecturl2})