'''
Functions in this file store information related to domain names.

iscdn
Requests for domains without 'www'
Query for historical IP information
Return the length of the requested response
'''
yellow = '\033[01;33m'
white = '\033[01;37m'
green = '\033[01;32m'
blue = '\033[01;34m'
red = '\033[1;31m'
end = '\033[0m'





import dns.resolver
import requests
import sys
def domain_handler(domain):
    if "http" not in domain or "www" not in domain:
        print("Incorrect format. Standard format: http://www.example.com")
        sys.exit(0)
    return domain
def domain_short(domain):
    domain=domain.lstrip("http://www.")
    domain=domain.lstrip("https://www.")
    return  domain
def iscdn(domain,ip_lis,port=80):
    '''
    Resolve A records by accessing DNS and then access common ports
    :param domain: Domain in the form example.com
    :param ip_list: List of resolved A records
    :param port: Default ports are 80 and 443
    :return: Determine if the domain is using CDN acceleration
    '''
    ans = dns.resolver.query(domain,'A')
    for i in ans.response.answer[-1].items:
        ip_lis.append(i.address)
    flag=0
    for ip in ip_lis:
        try:
            r=requests.get('http://'+ip+":"+str(port),timeout=2)
            code=r.status_code
        except:
            code=600
        try:
            r1 = requests.get('https://' + ip + ":443", timeout=2)
            code1 = r1.status_code
        except:
            code1=500

        if code< 400 or code1 <400 :  #Indicates that one of the IP addresses can be accessed
            flag=1
            break
    if flag:
        print(f'''{red}domain+"does not use CDN acceleration"''')
        return True
    else:
        print(f'''{green}domain+"uses CDN acceleration"''')
        return False
from urllib.parse import urlparse
def withoutwww(domain,ip_lis):
    '''
    :param domain: domain www.example.com
    :param ip_lis: Input ip_lis
    :return: List with domains without 'www'
    '''

    #Remove 'www' from the domain

    domain=domain.lstrip('www.')
    ans = dns.resolver.query(domain,'A') #Still query through DNS
    if ans:
        for i in ans.response.answer[-1].items:
            if i.address in ip_lis:
                continue
            print(f'''{green}Find a host without www{str(i.address)}''')
            ip_lis.append(i.address)

    return (ip_lis)
import config
import json
def history_ip(domain):
    '''
    :param ip_list: Input IP information
    :param domain: Domain information for the request, example.com
    :return: Data returned is still the list of operated IPs
    '''
    url = "https://api.securitytrails.com/v1/history/"+domain+"/dns/a"
    headers = {'accept': 'application/json',
               'APIKEY': config.securitytrail_key
               }
    raw_data = requests.request("GET", url, headers=headers)
    raw_data = json.loads(raw_data.text)
    t=0
    ip_lis=[]
    for i in (raw_data["records"]):
        for j in (i['values']):
            t+=1
            ip_lis.append(j['ip'])
    print(f'''{green}History get {str(t)} ip ''')
    return (list(set(ip_lis)))

def get_resp_len(url):
    # Return response body length
    '''
    Get the length of response body.
    '''
    res =999999
    try:
        r = requests.get(url, timeout=2)
        if r.status_code ==200:
            res = len(r.content)
    except:
        pass
    return res
