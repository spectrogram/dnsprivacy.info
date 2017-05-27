import sys
import dns.resolver
import dns.message
import dns.flags
from ipwhois import IPWhois
import getdns

# check if we can resolve using this resolver
def checkPublic(res):
   try:
      answer = res.query('google.com', 'A')
   except dns.exception.Timeout:
      return False

   return True

# resolver supporting DNSSEC should pass both tests
# resolver not supporting DNSSEC should fail both
def dnssecTest1(res):
   message = dns.message.make_query('verisign.com', 'A', want_dnssec=True)
   answer = dns.query.udp(message, res.nameservers[0], timeout=4)

   if answer.flags & dns.flags.AD:
      return True
   else:
      return False

def dnssecTest2(res):
   try:
      answer = res.query('dnssec-failed.org', 'A')
   except dns.resolver.NoNameservers:
      return True

   return False

# resolver should return NXDOMAIN
def nxdomainTest(res):
   try:
      answer = res.query('efukhekehf.fe8ijkfneofj.com', 'A')
   except dns.resolver.NXDOMAIN:
      return True

   return False

def censorshipTest1(res):
   try:
      answer = res.query('twitter.com', 'A')
   except dns.exception.Timeout:
      return False

   try:
      obj = IPWhois(answer.rrset[0])
   except ValueError:
      return False

   results = IPWhois.lookup_rdap(obj)
   if results["network"]["name"] == "TWITTER-NETWORK":
      return True
   else:
      return False

def censorshipTest2(res):
   try:
      answer = res.query('thepiratebay.org', 'A')
   except dns.exception.Timeout:
      return False

   try:
      obj = IPWhois(answer.rrset[0])
   except ValueError:
      return False

   results = IPWhois.lookup_rdap(obj)
   if results["network"]["name"] == "CLOUDFLARENET":
      return True
   else:
      return False

def censorshipTest3(res):
   try:
      answer = res.query('xvideos.com', 'A')
   except dns.exception.Timeout:
      return False

   res2 = dns.resolver.Resolver(configure=False)
   res2.timeout = 3
   res2.lifetime = 3
   res2.nameservers = ['8.8.8.8']

   try:
      answer2 = res2.query('xvideos.com', 'A')
   except dns.exception.Timeout:
      return True

   if answer.rrset[0] in answer2.rrset:
      return True

def dnsTLStest(res):
   transport = getdns.TRANSPORT_TLS
   context = getdns.Context()
   context.dns_transport_list = [ transport ]
   context.resolution_type = getdns.RESOLUTION_STUB
   server_dict = {'address_data': res.nameservers[0], 'address_type': 'IPv4'}
   context.upstream_recursive_servers = [server_dict]
   context.timeout = 3
   try:
      result = context.general('google.com', request_type=1)
      if status == getdns.RESPSTATUS_GOOD:
         return True
      else:
         return False
   except getdns.error:
      return False

# create resolver object
def createRes(ns):
   res = dns.resolver.Resolver(configure=False)
   res.timeout = 3
   res.lifetime = 3
   res.nameservers = [ns]
   return res

def main():
   try:
      ns = sys.argv[1]
   except IndexError:
      exit

   res = createRes(ns)
   if checkPublic(res):
      print "Is public? " + str(checkPublic(res))
      # print "NXDOMAIN " + str(nxdomainTest(res))
      # print "DNSSEC 1 " + str(dnssecTest1(res))
      # print "DNSSEC 2 " + str(dnssecTest2(res))
      # print "CENSORSHIP 1 (social media) " + str(censorshipTest1(res))
      # print "CENSORSHIP 2 (filesharing) " + str(censorshipTest2(res))
      # print "CENSORSHIP 3 (adult content) " + str(censorshipTest3(res))
      # print "DNS OVER TLS " + str(dnsTLStest(res))
   else:
      print "Nope"
      return False

if __name__ == '__main__':
   main()