import requests
import re

cert = ('/home/rohan/Desktop/comp6843/certificate', '/home/rohan/Desktop/comp6843/key')
flagre = r"COMP6443{[a-zA-Z0-9./=]*}"

class host(object):
    def __init__(self, domain: str, protocol: str="http", cookies: dict={}, 
                    proxies: dict={"http" : "127.0.0.1:8080"}, cert=None):
        self.domain: str = domain
        self.protocol: str = protocol
        self.cookies: dict = cookies
        self.proxies: dict = proxies
        self.cert: tuple = cert
    
    def basic_recon(self):
        paths_to_scan = ["", "/robots.txt", "/admin", "/.git", "/.gitignore", "/login"]
        targets = [target("GET", self, i) for i in paths_to_scan]
        for t in targets:
            t.simple_scan()

class target(object):
    def __init__(self, method: str, host: host, path: str="", data: dict={}, queryString: str="", 
                    vuln_field: str=None):
        self.method: str = method
        self.host: host = host
        self.path: str = path
        self.data: dict = data
        self.queryString: str = queryString
        self.vuln_field: str = vuln_field

        self.request_opts: dict = {"cookies" : host.cookies, "proxies" : host.proxies, "cert" : host.cert}

    def uri(self, qstring=None) -> str:
        qstring = self.queryString if qstring is None else qstring
        qstring = '?' + qstring if qstring != '' else ''
        return self.host.protocol + "://" + self.host.domain + self.path + qstring
    
    def send_request(self, qstring=None, data=None) -> requests.Response:
        if self.method == "POST":
            func = requests.post
        elif self.method == "GET":
            func = requests.get
        else:
            raise Exception("method not implemented")
        
        uri: str = self.uri(qstring=qstring)

        resp: requests.Response = func(uri, data=data, **self.request_opts)
        return resp
    
    def simple_scan(self) -> list:
        resp: requests.Response = self.send_request()
        print(resp.status_code)
        hstring = '##'.join(list(resp.headers.values()) + list(resp.headers.keys()))
        dom_flags = re.findall(r"COMP6443{[a-zA-Z0-9./=]*}", resp.text)
        header_flags = re.findall(r"COMP6443{[a-zA-Z0-9./=]*}", hstring)
        print(dom_flags)
        print(header_flags)
        out = {"status" : resp.status_code, "flags" : dom_flags + header_flags, "srcs" : [], "hrefs" : []}
        return out


m1 = host("midsem3.quoccabank.com", protocol="https", cert=cert)
m1.basic_recon()
# r = requests.get("http://midsem1.quoccabank.com", proxies={"http" : "127.0.0.1:8080"})
# print(r.text)