import re, sys
from ipwhois import IPWhois

def scanlog(ip):
   f = open('/var/log/querylog', 'r')
   ip = ip.replace(".", "-")
   for line in reversed(f.readlines()):
      if ip in line:
         result = re.findall(r'client ([0-9]+(?:\.[0-9]+){3})#', line)
         if not result:
            continue
         else:
            return result[0].lstrip()
      else:
         continue
   f.close()

def whois(ip):
   try:
      obj = IPWhois(ip)
   except ValueError:
      return None

   results = IPWhois.lookup_rdap(obj)
   return results["network"]["name"]

def scanlogqname(resolverip):
   f = open('/var/log/querylog', 'r')
   regex_string = r"\(minimisation\.dnsprivacy\.info\)"
   for line in reversed(f.readlines()):
      if resolverip in line:
         result = re.findall(regex_string, line)
         if not result:
            continue
         else:
            f.close()
            return True
      else:
         continue
         
   f.close()
   return False
   

if __name__ == '__main__':
   try:
      arg = sys.argv[1]
   except IndexError:
      exit

   return_val = scanlogqname(arg)
   print return_val

